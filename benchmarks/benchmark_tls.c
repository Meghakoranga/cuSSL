/* benchmark_tls.c - Multi-Threaded TLS 1.3 Load Generator for ML-KEM */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <time.h>

#define SERVER_PORT "4433"
#define HOST_NAME "localhost"

// GLOBAL STATS
int g_handshakes_completed = 0;
pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    int thread_id;
    int iterations;
    const char *port;   
    const char *group;

} thread_args;


void *worker_thread(void *arg) {
    thread_args *args = (thread_args *)arg;
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *bio;
    
    ctx = SSL_CTX_new(TLS_client_method());
if (!ctx) {
    fprintf(stderr, "Thread %d: Failed to create SSL_CTX\n", args->thread_id);
    return NULL;
}

SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

if (!SSL_CTX_set1_groups_list(ctx,args->group)) {
    fprintf(stderr, "Error: not supported by this OpenSSL build.\n");
    SSL_CTX_free(ctx);
    return NULL;
}

SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    for (int i = 0; i < args->iterations; i++) {
        //  Create Connection BIO
        bio = BIO_new_ssl_connect(ctx);
        if (!bio) {
             fprintf(stderr, "Thread %d: BIO creation failed\n", args->thread_id);
             continue;
        }

        char target[64];
        snprintf(target, sizeof(target), "127.0.0.1:%s", args->port);
        BIO_set_conn_hostname(bio, target);

        BIO_get_ssl(bio, &ssl); 

        if (!ssl) {
             fprintf(stderr, "Thread %d: Could not get SSL pointer\n", args->thread_id);
             BIO_free_all(bio);
             continue;
        }

        SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

        //  Perform Handshake
        // We use BIO_do_connect first to establish TCP, then handshake
        if (BIO_do_connect(bio) <= 0) {
             // Connection failed (Server might be busy/full)
             // Uncomment this line only if you need to debug connection errors:
              ERR_print_errors_fp(stderr);
             BIO_free_all(bio);
             continue;
        }

        if (SSL_do_handshake(ssl) <= 0) {
            // Handshake failed
             ERR_print_errors_fp(stderr);
        } else {
#ifdef VERBOSE
            const char *cipher = SSL_get_cipher(ssl);
            printf("Handshake completed using: %s\n", cipher);
            fprintf(stderr, "Negotiated group NID: %d\n", SSL_get_negotiated_group(ssl));
#endif

            // Success!
            pthread_mutex_lock(&g_lock);
            g_handshakes_completed++;
            pthread_mutex_unlock(&g_lock);
        }

        // 5. Cleanup
        BIO_free_all(bio); // This frees the SSL object attached to it
    }

    SSL_CTX_free(ctx);
    return NULL;
}

int main(int argc, char **argv) {
     OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, NULL); 
    int num_threads = 64;   
    int total_iters = 10000; 
    const char *port = "4433";
    const char *group = "mlkem768";


    if (argc > 1) num_threads = atoi(argv[1]);
    if (argc > 2) total_iters = atoi(argv[2]);
    if (argc > 3) port = argv[3];
    if (argc > 4) group = argv[4];


    int iters_per_thread = total_iters / num_threads;
    
    printf("Starting TLS Benchmark (ML-KEM-768)\n");
    printf("Threads: %d | Total Requests: %d\n", num_threads, num_threads * iters_per_thread);

    pthread_t *threads = malloc(sizeof(pthread_t) * num_threads);
    thread_args *t_args = malloc(sizeof(thread_args) * num_threads);

    struct timespec ts_start, ts_end;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    // Launch Threads
    for (int i = 0; i < num_threads; i++) {
        t_args[i].thread_id = i;
        t_args[i].iterations = iters_per_thread;
        t_args[i].port = port;
        t_args[i].group = group;

        pthread_create(&threads[i], NULL, worker_thread, &t_args[i]);
    }

    // Wait for Threads
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    // End Timer
    clock_gettime(CLOCK_MONOTONIC, &ts_end);
    double time_spent = (ts_end.tv_sec - ts_start.tv_sec) + 
                        (ts_end.tv_nsec - ts_start.tv_nsec) / 1e9;

    printf("\n--- TLS Results ---\n");
    printf("Handshakes: %d\n", g_handshakes_completed);
    printf("Time:       %.2f sec\n", time_spent);
    printf("Rate:       %.2f Handshakes/Sec\n", g_handshakes_completed / time_spent);

    free(threads);
    free(t_args);
    return 0;
}
