#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <syslog.h>
#include <limits.h>
#include <signal.h>
#include <fcntl.h>
#include <openssl/evp.h>

#define HASH_SIZE EVP_MAX_MD_SIZE

// Struktura przechowująca informacje o plikach
typedef struct FileState {
    char *filename;
    unsigned char hash[HASH_SIZE];
    unsigned int hash_len;
    struct FileState *next;
} FileState;

// Zmienna globalna do obsługi sygnału
volatile sig_atomic_t wakeup_signal_received = 0;

// Funkcja obsługi sygnału
void handle_signal(int sig) {
    if (sig == SIGUSR1) {
        wakeup_signal_received = 1;
    }
}

// Funkcja do sprawdzenia, czy ścieżka jest katalogiem
int is_directory(const char *path) {
    struct stat statbuf;
    if (stat(path, &statbuf) != 0) {
        return 0;
    }
    return S_ISDIR(statbuf.st_mode);
}

// Funkcja do dodawania nowego pliku do listy plików
void add_file_state(FileState **head, const char *filename, const unsigned char *hash, unsigned int hash_len) {
    FileState *new_node = (FileState *)malloc(sizeof(FileState));
    new_node->filename = strdup(filename);
    memcpy(new_node->hash, hash, hash_len);
    new_node->hash_len = hash_len;
    new_node->next = *head;
    *head = new_node;
}

// Funkcja do obliczania sumy kontrolnej SHA-256 pliku za pomocą nowego API OpenSSL
int calculate_file_hash(const char *path, unsigned char *hash, unsigned int *hash_len) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        syslog(LOG_ERR, "Error opening file %s: %s", path, strerror(errno));
        return -1;
    }

    EVP_MD_CTX *mdctx;
    if ((mdctx = EVP_MD_CTX_new()) == NULL) {
        syslog(LOG_ERR, "Error creating EVP_MD_CTX");
        close(fd);
        return -1;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        syslog(LOG_ERR, "Error initializing digest");
        EVP_MD_CTX_free(mdctx);
        close(fd);
        return -1;
    }

    char buffer[4096];
    ssize_t bytes_read;
    while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0) {
        if (EVP_DigestUpdate(mdctx, buffer, bytes_read) != 1) {
            syslog(LOG_ERR, "Error updating digest");
            EVP_MD_CTX_free(mdctx);
            close(fd);
            return -1;
        }
    }

    if (bytes_read < 0) {
        syslog(LOG_ERR, "Error reading file %s: %s", path, strerror(errno));
        EVP_MD_CTX_free(mdctx);
        close(fd);
        return -1;
    }

    if (EVP_DigestFinal_ex(mdctx, hash, hash_len) != 1) {
        syslog(LOG_ERR, "Error finalizing digest");
        EVP_MD_CTX_free(mdctx);
        close(fd);
        return -1;
    }

    EVP_MD_CTX_free(mdctx);
    close(fd);
    return 0;
}

// Funkcja do kopiowania plików za pomocą niskopoziomowych operacji read/write
void copy_file(const char *src_path, const char *dest_path) {
    int src_fd, dest_fd;
    char buffer[4096];
    ssize_t bytes_read, bytes_written;

    src_fd = open(src_path, O_RDONLY);
    if (src_fd < 0) {
        syslog(LOG_ERR, "Error opening source file %s: %s", src_path, strerror(errno));
        return;
    }

    dest_fd = open(dest_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dest_fd < 0) {
        syslog(LOG_ERR, "Error opening destination file %s: %s", dest_path, strerror(errno));
        close(src_fd);
        return;
    }

    while ((bytes_read = read(src_fd, buffer, sizeof(buffer))) > 0) {
        bytes_written = write(dest_fd, buffer, bytes_read);
        if (bytes_written != bytes_read) {
            syslog(LOG_ERR, "Error writing to file %s: %s", dest_path, strerror(errno));
            break;
        }
    }

    if (bytes_read < 0) {
        syslog(LOG_ERR, "Error reading from file %s: %s", src_path, strerror(errno));
    }

    close(src_fd);
    close(dest_fd);
}

// Funkcja do tworzenia brakujących katalogów w ścieżce docelowej
void create_dest_dir(const char *path) {
    char temp_path[PATH_MAX];
    strncpy(temp_path, path, sizeof(temp_path));
    temp_path[PATH_MAX - 1] = '\0';

    for (char *p = temp_path + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(temp_path, S_IRWXU);
            *p = '/';
        }
    }
    mkdir(temp_path, S_IRWXU);
}

// Funkcja do synchronizacji katalogów rekurencyjnie
void sync_directories_recursive(const char *src_path, const char *dest_path) {
    DIR *dir;
    struct dirent *entry;
    char src_full_path[PATH_MAX];
    char dest_full_path[PATH_MAX];

    if ((dir = opendir(src_path)) == NULL) {
        perror("opendir");
        syslog(LOG_ERR, "Error opening source directory: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        snprintf(src_full_path, sizeof(src_full_path), "%s/%s", src_path, entry->d_name);
        snprintf(dest_full_path, sizeof(dest_full_path), "%s/%s", dest_path, entry->d_name);

        if (entry->d_type == DT_REG) {
            create_dest_dir(dest_path);  // Tworzymy katalogi tylko do pliku docelowego
            copy_file(src_full_path, dest_full_path);
            syslog(LOG_INFO, "Copied file: %s", src_full_path);
        } else if (entry->d_type == DT_DIR) {
            create_dest_dir(dest_full_path);  // Tworzymy podkatalogi
            sync_directories_recursive(src_full_path, dest_full_path);
        }
    }

    closedir(dir);
}

// Funkcja do skanowania katalogu i tworzenia struktury danych zawierającej aktualny stan plików
void scan_directory(const char *base_path, const char *path, FileState **file_state_list) {
    DIR *dir;
    struct dirent *entry;
    char full_path[PATH_MAX];
    char rel_path[PATH_MAX];

    if ((dir = opendir(path)) == NULL) {
        perror("opendir");
        syslog(LOG_ERR, "Error opening directory: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);
        snprintf(rel_path, sizeof(rel_path), "%s/%s", path + strlen(base_path) + 1, entry->d_name);

        if (entry->d_type == DT_REG) {
            unsigned char hash[HASH_SIZE];
            unsigned int hash_len;
            if (calculate_file_hash(full_path, hash, &hash_len) == 0) {
                add_file_state(file_state_list, rel_path, hash, hash_len);
            }
        } else if (entry->d_type == DT_DIR) {
            scan_directory(base_path, full_path, file_state_list);
        }
    }

    closedir(dir);
}

// Funkcja do porównywania stanu plików i wykonywania odpowiednich operacji
void compare_and_update(FileState **old_state, FileState *new_state, const char *src_path, const char *dest_path) {
    FileState *current_old = *old_state;
    FileState *current_new = new_state;
    FileState *prev_old = NULL;

    // Sprawdzanie nowych i zmodyfikowanych plików
    while (current_new != NULL) {
        int found = 0;
        current_old = *old_state;
        prev_old = NULL;

        while (current_old != NULL) {
            if (strcmp(current_new->filename, current_old->filename) == 0) {
                found = 1;
                if (memcmp(current_new->hash, current_old->hash, current_new->hash_len) != 0) {
                    char src_file_path[PATH_MAX], dest_file_path[PATH_MAX];
                    snprintf(src_file_path, sizeof(src_file_path), "%s/%s", src_path, current_new->filename);
                    snprintf(dest_file_path, sizeof(dest_file_path), "%s/%s", dest_path, current_new->filename);

                    create_dest_dir(dest_file_path);  // Tworzymy katalogi tylko do pliku docelowego
                    copy_file(src_file_path, dest_file_path);
                    syslog(LOG_INFO, "File modified: %s", current_new->filename);

                    memcpy(current_old->hash, current_new->hash, current_new->hash_len);
                    current_old->hash_len = current_new->hash_len;
                }
                break;
            }
            prev_old = current_old;
            current_old = current_old->next;
        }

        if (!found) {
            syslog(LOG_INFO, "New file: %s", current_new->filename);
            char src_file_path[PATH_MAX], dest_file_path[PATH_MAX];
            snprintf(src_file_path, sizeof(src_file_path), "%s/%s", src_path, current_new->filename);
            snprintf(dest_file_path, sizeof(dest_file_path), "%s/%s", dest_path, current_new->filename);

            create_dest_dir(dest_file_path);  // Tworzymy katalogi tylko do pliku docelowego
            copy_file(src_file_path, dest_file_path);
            add_file_state(old_state, current_new->filename, current_new->hash, current_new->hash_len);
        }

        current_new = current_new->next;
    }

    // Sprawdzanie usuniętych plików
    current_old = *old_state;
    prev_old = NULL;

    while (current_old != NULL) {
        current_new = new_state;
        int found = 0;

        while (current_new != NULL) {
            if (strcmp(current_new->filename, current_old->filename) == 0) {
                found = 1;
                break;
            }
            current_new = current_new->next;
        }

        if (!found) {
            syslog(LOG_INFO, "File deleted: %s", current_old->filename);
            if (prev_old == NULL) {
                *old_state = current_old->next;
            } else {
                prev_old->next = current_old->next;
            }
            free(current_old->filename);
            FileState *temp = current_old;
            current_old = current_old->next;
            free(temp);
        } else {
            prev_old = current_old;
            current_old = current_old->next;
        }
    }
}

// Funkcja do zwalniania pamięci zajmowanej przez listę plików
void free_file_state_list(FileState *head) {
    FileState *tmp;
    while (head != NULL) {
        tmp = head;
        head = head->next;
        free(tmp->filename);
        free(tmp);
    }
}

// Funkcja demona
void daemonize(const char *src_path, const char *dest_path, int sleep_time, int recursive) {
    pid_t pid, sid;

    // Utworzenie nowego procesu
    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    // Zmiana umask
    umask(0);

    // Utworzenie nowej sesji
    sid = setsid();
    if (sid < 0) {
        exit(EXIT_FAILURE);
    }

    // Zmiana katalogu roboczego
    if ((chdir("/")) < 0) {
        exit(EXIT_FAILURE);
    }

    // Zamknięcie standardowych deskryptorów plików
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    // Otwarcie sysloga
    openlog("FileMonitorDaemon", LOG_PID, LOG_DAEMON);
    syslog(LOG_INFO, "Daemon started");

    // Ustawienie obsługi sygnału
    struct sigaction sa;
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGUSR1, &sa, NULL) == -1) {
        syslog(LOG_ERR, "Error setting up signal handler: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    FileState *file_state_list = NULL;

    // Początkowe skanowanie katalogu
    scan_directory(src_path, src_path, &file_state_list);

    while (1) {
        if (wakeup_signal_received) {
            syslog(LOG_INFO, "Woken up by SIGUSR1");
            wakeup_signal_received = 0;
        } else {
            syslog(LOG_INFO, "Waking up after sleep");
        }

        FileState *new_file_state_list = NULL;
        scan_directory(src_path, src_path, &new_file_state_list);

        compare_and_update(&file_state_list, new_file_state_list, src_path, dest_path);

        free_file_state_list(new_file_state_list);

        if (recursive) {
            sync_directories_recursive(src_path, dest_path);
        }

        syslog(LOG_INFO, "Going to sleep");
        sleep(sleep_time);
    }

    // Zamknięcie sysloga
    closelog();
}

int main(int argc, char *argv[]) {
    int recursive = 0;

    if (argc < 3 || argc > 5) {
        fprintf(stderr, "Usage: %s <source_path> <destination_path> [-R] [sleep_time]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *src_path = argv[1];
    const char *dest_path = argv[2];
    int sleep_time = 300;

    if (argc == 4) {
        if (strcmp(argv[3], "-R") == 0) {
            recursive = 1;
        } else {
            sleep_time = atoi(argv[3]);
        }
    }

    if (argc == 5) {
        if (strcmp(argv[3], "-R") == 0) {
            recursive = 1;
            sleep_time = atoi(argv[4]);
        } else if (strcmp(argv[4], "-R") == 0) {
            recursive = 1;
            sleep_time = atoi(argv[3]);
        } else {
            fprintf(stderr, "Usage: %s <source_path> <destination_path> [-R] [sleep_time]\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if (!is_directory(src_path) || !is_directory(dest_path)) {
        fprintf(stderr, "Error: Both paths must be directories.\n");
        exit(EXIT_FAILURE);
    }

    if (recursive) {
        syslog(LOG_INFO, "Recursive synchronization enabled");
    }

    daemonize(src_path, dest_path, sleep_time, recursive);

    return 0;
}