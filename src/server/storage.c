#include "server/storage.h"
#include "log.h"

#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define STORAGE_PATH "STORAGE_PATH"

char *server_storage_path = NULL;

int storage_init(const char *server_id)
{
    const char *storage_path = getenv(STORAGE_PATH);
    if (storage_path == NULL) {
        LOG_ERROR("STORAGE_PATH is undefined");
        return EXIT_FAILURE;
    }

    int storage_dir = mkdir(storage_path, 0755);
    if (storage_dir < 0 && errno != EEXIST) {
        LOG_ERROR("Storage dir error");
        return EXIT_FAILURE;
    }

    if (asprintf(&server_storage_path, "%s/%s", storage_path, server_id) < 0) {
        LOG_ERROR("Server storage path error");
        return EXIT_FAILURE;
    }

    int server_storage_dir = mkdir(server_storage_path, 0755);
    if (server_storage_dir < 0 && errno != EEXIST) {
        LOG_ERROR("Server storage dir error");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static int remove_directory_recursive(const char *path)
{
    DIR *dir = opendir(path);
    if (!dir)
        return -1;

    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        char full_path[1024];
        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);

        struct stat st;
        if (stat(full_path, &st) < 0)
            return -1;

        if (S_ISDIR(st.st_mode)) {
            if (remove_directory_recursive(full_path) < 0)
                return -1;
        } else {
            if (unlink(full_path) < 0)
                return -1;
        }
    }

    closedir(dir);

    return rmdir(path);
}

int storage_deinit()
{
    if (!server_storage_path)
        return EXIT_FAILURE;

    if (remove_directory_recursive(server_storage_path) < 0) {
        LOG_ERROR("Failed to delete storage directory");
        return EXIT_FAILURE;
    }

    free(server_storage_path);
    server_storage_path = NULL;

    return EXIT_SUCCESS;
}

int storage_store_secret(const char *client_id, unsigned char *phi0,
                         uint16_t phi0_len_out, unsigned char *c, uint16_t c_len_out)
{
    char *client_path = NULL;
    FILE *file = NULL;

    int result = EXIT_SUCCESS;

    if (!server_storage_path) {
        LOG_ERROR("Server storage path is NULL");
        result = EXIT_FAILURE;
        goto cleanup;
    }

    if (asprintf(&client_path, "%s/%s", server_storage_path, client_id) < 0) {
        LOG_ERROR("Client secret file path error");
        result = EXIT_FAILURE;
        goto cleanup;
    }

    file = fopen(client_path, "w");
    if (!file) {
        LOG_ERROR("While opening secret file");
        result = EXIT_FAILURE;
        goto cleanup;
    }

    fwrite(&phi0_len_out, sizeof(uint16_t), 1, file);
    fwrite(phi0, 1, phi0_len_out, file);

    fwrite(&c_len_out, sizeof(uint16_t), 1, file);
    fwrite(c, 1, c_len_out, file);

cleanup:
    if (file) {
        fclose(file);
    }
    free(client_path);

    return result;
}

VerifyResult storage_verify_secret(const char *client_id, unsigned char *phi0,
                                   uint16_t phi0_len_out, unsigned char *c,
                                   uint16_t c_len_out)
{
    char *client_path = NULL;
    FILE *file = NULL;

    int result = VR_SUCCESS;

    if (!server_storage_path) {
        LOG_ERROR("Server storage path is NULL");
        result = VR_FAILURE;
        goto cleanup;
    }

    if (asprintf(&client_path, "%s/%s", server_storage_path, client_id) < 0) {
        LOG_ERROR("Client secret file path error");
        result = VR_FAILURE;
        goto cleanup;
    }

    file = fopen(client_path, "r");
    if (!file) {
        result = VR_NOT_FOUND;
        goto cleanup;
    }

    uint16_t len;
    // reading and comparing length of phi0
    fread(&len, sizeof(uint16_t), 1, file);
    if (len != phi0_len_out) {
        result = VR_NOT_VALID;
        goto cleanup;
    }
    unsigned char *buffer = malloc(len);

    // reading and comparing phi0
    fread(buffer, 1, len, file);
    if (memcmp(phi0, buffer, len) != 0) {
        result = VR_NOT_VALID;
        goto cleanup;
    }

    // reading and comparing length of c
    fread(&len, sizeof(uint16_t), 1, file);
    if (len != c_len_out) {
        result = VR_NOT_VALID;
        goto cleanup;
    }

    // reading and comparing c
    fread(buffer, 1, len, file);
    if (memcmp(c, buffer, len) != 0) {
        result = VR_NOT_VALID;
        goto cleanup;
    }

cleanup:
    if (file) {
        fclose(file);
    }
    free(client_path);

    return result;
}
