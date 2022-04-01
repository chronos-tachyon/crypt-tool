/* crypt: tiny program to implement crypt(3) as a CLI */

#include <crypt.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

static const char* const USAGE =
  "Hashes one or more passwords from the terminal or stdin.\n"
  "Usage: crypt [<prefix> [<rounds>]]\n"
  "\n"
  "Example command line session:\n"
  "\n"
  "\t$ crypt '$2b' 12\n"
  "\tPassword: <password is typed, followed by Enter>\n"
  "\tHash: $2b$12$Z0vgnP2jil4YioUAGsDwa.nIkRS.we6hBNHyy4WutXlPT3V5D/ktO\n"
  "\tPassword: <Enter is pressed immediately>\n"
  "\t<program exits>\n"
  "\t$ \n"
  "\n"
  "<prefix> is a string, such as \"$2b$\", that selects an algorithm for\n"
  "the generated password hashes.  See crypt(5) for a list of supported\n"
  "algorithms.  If not specified, NULL is provided, which the manpage for\n"
  "crypt_gensalt(3) says is supposed to select \"the best available hashing\n"
  "method\", whatever that means.\n"
  "\n"
  "<rounds> is the number of \"rounds\" of hashing to apply.  Only some\n"
  "algorithms use this value, and the meaning depends on which algorithm is\n"
  "selected.  If not specified, 0 is provided, which tells the selected\n"
  "algorithm to use its best judgement.\n"
  "\n"
  "The input behavior depends on whether or not stdin is a terminal.\n"
  "\n";

static struct termios old_config;
static int use_tty = 0;
static int tty_fd = 0;
static int need_flush = 0;

static struct crypt_data *storage_ptr = NULL;
static char *entropy_ptr = NULL;
static int storage_len = 0;
static int entropy_len = 0;

static void force_tty_echo_off() {
  struct termios new_config;
  memcpy(&new_config, &old_config, sizeof(old_config));
  new_config.c_lflag &= ~ECHO;
  tcsetattr(tty_fd, TCSAFLUSH, &new_config);
}

static void restore_tty() {
  tcsetattr(tty_fd, TCSAFLUSH, &old_config);
  if (need_flush) {
    ssize_t n = write(1, "\n", 1);
    (void)n; /* intentionally unused */
  }
}

static void clear_sensitive_memory() {
  if (entropy_ptr != NULL) {
    explicit_bzero(entropy_ptr, entropy_len);
  }

  if (storage_ptr != NULL) {
    explicit_bzero(storage_ptr, storage_len);
  }
}

static void free_sensitive_memory() {
  if (entropy_ptr != NULL) {
    explicit_bzero(entropy_ptr, entropy_len);
    munmap(entropy_ptr, entropy_len);
  }

  if (storage_ptr != NULL) {
    explicit_bzero(storage_ptr, storage_len);
    munmap(storage_ptr, storage_len);
  }
}

static void on_signal(int sig, siginfo_t *info, void *ucontext) {
  restore_tty();
  free_sensitive_memory();
  pid_t my_pid = getpid();
  kill(my_pid, sig);
}

int main(int argc, char **argv) {
  if (CRYPT_GENSALT_OUTPUT_SIZE > CRYPT_OUTPUT_SIZE) {
    fprintf(stderr,
            "fatal: CRYPT_GENSALT_OUTPUT_SIZE=%zd > CRYPT_OUTPUT_SIZE=%zd",
            (ssize_t)CRYPT_GENSALT_OUTPUT_SIZE, (ssize_t)CRYPT_OUTPUT_SIZE);
    exit(1);
  }

  const char *prefix = NULL;
  if (argc >= 2 && argv[1][0] != '\0') {
    prefix = argv[1];
  }

  if (strcmp(prefix, "-h") == 0 ||
      strcmp(prefix, "--help") == 0) {
    fputs(USAGE, stdout);
    exit(0);
  }

  unsigned long count = 0;
  if (argc >= 3 && argv[2][0] != '\0') {
    char *endptr = argv[2];
    count = strtoul(argv[2], &endptr, 10);
    if (endptr[0] != '\0') {
      perror("strtoul");
      exit(1);
    }
  }

  FILE *tty_file = stdout;
  if (isatty(0)) {
    tty_fd = open("/dev/tty", O_RDWR, 0);
    if (tty_fd == -1) {
      perror("open /dev/tty");
      exit(1);
    }

    tty_file = fdopen(tty_fd, "r+");
    if (tty_file == NULL) {
      perror("fdopen tty_fd");
      exit(1);
    }

    bzero(&old_config, sizeof(old_config));
    int rc = tcgetattr(tty_fd, &old_config);
    if (rc != 0) {
      perror("tcgetattr");
      exit(1);
    }

    struct sigaction sa;
    bzero(&sa, sizeof(sa));
    sa.sa_sigaction = on_signal;
    sa.sa_flags = (SA_SIGINFO | SA_RESETHAND);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);

    use_tty = 1;
  }

  int entropy_fd = open("/dev/urandom", O_RDONLY, 0);
  if (entropy_fd == -1) {
    perror("open /dev/urandom");
    exit(1);
  }

  storage_len = sizeof(struct crypt_data);
  storage_ptr = (struct crypt_data *)mmap(
      NULL, storage_len, PROT_READ | PROT_WRITE,
      MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);
  if (storage_ptr == NULL) {
    perror("mmap");
    exit(1);
  }

  entropy_len = 1024;
  entropy_ptr = (char *)mmap(NULL, entropy_len, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);
  if (storage_ptr == NULL) {
    perror("mmap");
    exit(1);
  }

  char *password = storage_ptr->input;

  int looping = 1;
  while (looping) {
    clear_sensitive_memory();

    ssize_t n = read(entropy_fd, entropy_ptr, entropy_len);
    if (n == -1) {
      perror("read /dev/urandom");
      free_sensitive_memory();
      exit(1);
    }

    if (use_tty) {
      fputs("Password: ", tty_file);
      fflush(tty_file);
      force_tty_echo_off();
    }

    int password_len = 0;
    int max_password_len = CRYPT_MAX_PASSPHRASE_SIZE - 1;
    while (password_len < max_password_len) {
      ssize_t n = read(tty_fd, password + password_len, 1);

      if (n == -1) {
        perror("read /dev/tty");
        restore_tty();
        free_sensitive_memory();
        exit(1);
      }

      if (n == 0) {
        break;
      }

      need_flush = 1;

      int ch = (unsigned char)password[password_len];
      if (ch == '\n') {
        password[password_len] = '\0';
        break;
      }

      password_len++;
    }

    if (use_tty) {
      restore_tty();
    }

    if (password_len == 0) {
      break;
    }

    int ok = 1;
    for (int i = 0; i < password_len; i++) {
      int ch = (unsigned char)password[i];
      if (ch < 0x20) {
        fprintf(stderr, "error: control character 0x%02x in password\n", ch);
        ok = 0;
        break;
      }
    }

    if (!ok) {
      continue;
    }

    char *salt = crypt_gensalt_rn(prefix, count, NULL, 0, storage_ptr->setting,
                                  CRYPT_OUTPUT_SIZE);
    if (salt == NULL) {
      perror("crypt_gensalt_rn");
      storage_ptr->setting[CRYPT_OUTPUT_SIZE - 1] = '\0';
      fputs(storage_ptr->setting, stderr);
      fputs("\n", stderr);
      free_sensitive_memory();
      exit(1);
    }

    char *hash = crypt_rn(password, salt, storage_ptr, storage_len);
    if (hash == NULL) {
      perror("crypt_rn");
      storage_ptr->output[CRYPT_OUTPUT_SIZE - 1] = '\0';
      fputs(storage_ptr->output, stderr);
      fputs("\n", stderr);
      free_sensitive_memory();
      exit(1);
    }

    fputs("Hash: ", stdout);
    fputs(hash, stdout);
    fputs("\n", stdout);
    fflush(stdout);
  }

  if (use_tty) {
    fclose(tty_file);
  }

  free_sensitive_memory();
  close(entropy_fd);

  return 0;
}
