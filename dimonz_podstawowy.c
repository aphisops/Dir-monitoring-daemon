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

// Struktura przechowuj¹ca informacje o plikach
typedef struct FileState {
    char* filename;
    time_t mod_time;
    off_t size;
    struct FileState* next;
} FileState;

// Zmienna globalna do obs³ugi sygna³u
volatile sig_atomic_t wakeup_signal_received = 0;

// Funkcja obs³ugi sygna³u
void handle_signal(int sig) {
    if (sig == SIGUSR1) {
        wakeup_signal_received = 1;
    }
}

// Funkcja do sprawdzenia, czy œcie¿ka jest katalogiem
int is_directory(const char* path) {
    struct stat statbuf;
    if (stat(path, &statbuf) != 0) {
        return 0;
    }
    return S_ISDIR(statbuf.st_mode);
}

// Funkcja do dodawania nowego pliku do listy plików
void add_file_state(FileState** head, const char* filename, time_t mod_time, off_t size) {
    FileState* new_node = (FileState*)malloc(sizeof(FileState));
    new_node->filename = strdup(filename);
    new_node->mod_time = mod_time;
    new_node->size = size;
    new_node->next = *head;
    *head = new_node;
}

// Funkcja do skanowania katalogu i tworzenia struktury danych zawieraj¹cej aktualny stan plików
void scan_directory(const char* path, FileState** file_state_list) {
    DIR* dir;
    struct dirent* entry;
    struct stat statbuf;
    char full_path[PATH_MAX];

    if ((dir = opendir(path)) == NULL) {
        perror("opendir");
        syslog(LOG_ERR, "Error opening directory: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {
            snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);
            if (stat(full_path, &statbuf) == 0) {
                add_file_state(file_state_list, entry->d_name, statbuf.st_mtime, statbuf.st_size);
            }
        }
    }

    closedir(dir);
}

// Funkcja do kopiowania plików za pomoc¹ niskopoziomowych operacji read/write
void copy_file(const char* src_path, const char* dest_path) {
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

// Funkcja do porównywania stanu plików i wykonywania odpowiednich operacji
void compare_and_update(FileState** old_state, FileState* new_state, const char* src_path, const char* dest_path) {
    FileState* current_old = *old_state;
    FileState* current_new = new_state;
    FileState* prev_old = NULL;

    // Sprawdzanie nowych i zmodyfikowanych plików
    while (current_new != NULL) {
        int found = 0;
        current_old = *old_state;
        prev_old = NULL;

        while (current_old != NULL) {
            if (strcmp(current_new->filename, current_old->filename) == 0) {
                found = 1;
                if (current_new->mod_time != current_old->mod_time || current_new->size != current_old->size) {
                    char src_file_path[PATH_MAX], dest_file_path[PATH_MAX];
                    snprintf(src_file_path, sizeof(src_file_path), "%s/%s", src_path, current_new->filename);
                    snprintf(dest_file_path, sizeof(dest_file_path), "%s/%s", dest_path, current_new->filename);

                    copy_file(src_file_path, dest_file_path);
                    syslog(LOG_INFO, "File modified: %s", current_new->filename);

                    current_old->mod_time = current_new->mod_time;
                    current_old->size = current_new->size;
                }
                break;
            }
            prev_old = current_old;
            current_old = current_old->next;
        }

        if (!found) {
            syslog(LOG_INFO, "New file: %s", current_new->filename);
            add_file_state(old_state, current_new->filename, current_new->mod_time, current_new->size);
        }

        current_new = current_new->next;
    }

    // Sprawdzanie usuniêtych plików
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
            }
            else {
                prev_old->next = current_old->next;
            }
            free(current_old->filename);
            FileState* temp = current_old;
            current_old = current_old->next;
            free(temp);
        }
        else {
            prev_old = current_old;
            current_old = current_old->next;
        }
    }
}

// Funkcja do zwalniania pamiêci zajmowanej przez listê plików
void free_file_state_list(FileState* head) {
    FileState* tmp;
    while (head != NULL) {
        tmp = head;
        head = head->next;
        free(tmp->filename);
        free(tmp);
    }
}

// Funkcja demona
void daemonize(const char* src_path, const char* dest_path, int sleep_time) {
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

    // Zamkniêcie standardowych deskryptorów plików
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    // Otwarcie sysloga
    openlog("FileMonitorDaemon", LOG_PID, LOG_DAEMON);
    syslog(LOG_INFO, "Daemon started");

    // Ustawienie obs³ugi sygna³u
    struct sigaction sa;
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGUSR1, &sa, NULL) == -1) {
        syslog(LOG_ERR, "Error setting up signal handler: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    FileState* file_state_list = NULL;

    // Pocz¹tkowe skanowanie katalogu
    scan_directory(src_path, &file_state_list);

    while (1) {
        if (wakeup_signal_received) {
            syslog(LOG_INFO, "Woken up by SIGUSR1");
            wakeup_signal_received = 0;
        }
        else {
            syslog(LOG_INFO, "Waking up after sleep");
        }

        FileState* new_file_state_list = NULL;
        scan_directory(src_path, &new_file_state_list);

        compare_and_update(&file_state_list, new_file_state_list, src_path, dest_path);

        free_file_state_list(new_file_state_list);

        syslog(LOG_INFO, "Going to sleep");
        sleep(sleep_time);
    }

    // Zamkniêcie sysloga
    closelog();
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <source_path> <destination_path> [sleep_time]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char* src_path = argv[1];
    const char* dest_path = argv[2];
    int sleep_time = (argc > 3) ? atoi(argv[3]) : 300;

    if (!is_directory(src_path) || !is_directory(dest_path)) {
        fprintf(stderr, "Error: Both paths must be directories.\n");
        exit(EXIT_FAILURE);
    }

    daemonize(src_path, dest_path, sleep_time);

    return 0;
}