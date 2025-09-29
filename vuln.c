/*
 * Comprehensive Test File for C Vulnerability Scanner
 * Tests both real vulnerabilities and false positive cases
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_NAME 50
#define BUFFER_SIZE 256

// Test struct for array bounds testing
typedef struct {
    char name[30];
    int id;
    char email[50];
} User;

// ============================================================
// SECTION 1: Safe strcpy() - Should NOT be flagged
// ============================================================

void safe_strcpy_short_literals() {
    char buffer[100];
    char name[50];
    char small[10];
    
    // All of these are SAFE - literals fit in buffers
    strcpy(buffer, "Hello");           // 6 bytes into 100
    strcpy(name, "John Doe");          // 9 bytes into 50
    strcpy(small, "Test");             // 5 bytes into 10
    strcpy(buffer, "A");               // 2 bytes into 100
    strcpy(name, "Anonymous");         // 10 bytes into 50
}

void safe_strcpy_with_structs() {
    User user;
    
    // SAFE - literals fit in struct members
    strcpy(user.name, "Alice Smith");     // 12 bytes into 30
    strcpy(user.email, "alice@test.com"); // 15 bytes into 50
}

// ============================================================
// SECTION 2: Unsafe strcpy() - SHOULD be flagged
// ============================================================

void unsafe_strcpy_variable_source(char *input) {
    char buffer[50];
    
    // UNSAFE - copying from variable (unknown length)
    strcpy(buffer, input);
}

void unsafe_strcpy_literal_too_long() {
    char tiny[10];
    
    // UNSAFE - literal is 26 bytes but buffer is only 10
    strcpy(tiny, "This string is way too long for the buffer");
}

void unsafe_strcpy_from_user() {
    char dest[20];
    char source[100];
    
    fgets(source, sizeof(source), stdin);
    // UNSAFE - source could be up to 100 bytes
    strcpy(dest, source);
}

// ============================================================
// SECTION 3: Array Declarations - Should NOT be flagged
// ============================================================

void array_declarations() {
    // These are declarations, not accesses - should NOT be flagged
    char name[20];
    int numbers[100];
    float values[50];
    char buffer[256];
    
    // Initialize safely
    name[0] = '\0';
    numbers[0] = 0;
}

typedef struct {
    char username[32];  // Declaration - should NOT be flagged
    char password[64];  // Declaration - should NOT be flagged
    int data[128];      // Declaration - should NOT be flagged
} Account;

// ============================================================
// SECTION 4: Array Out of Bounds - SHOULD be flagged
// ============================================================

void array_out_of_bounds() {
    int arr[10];
    char buf[20];
    
    // UNSAFE - accessing beyond array bounds
    arr[10] = 42;    // Array is 0-9, accessing 10
    arr[15] = 100;   // Way out of bounds
    buf[20] = 'X';   // Array is 0-19, accessing 20
    buf[25] = 'Y';   // Out of bounds
}

void loop_without_bounds_check() {
    int data[50];
    int i;
    
    // UNSAFE - loop might go beyond bounds
    for (i = 0; i <= 50; i++) {
        data[i] = i * 2;
    }
}

void safe_array_access() {
    int values[100];
    
    // SAFE - proper bounds checking
    for (int i = 0; i < 100; i++) {
        values[i] = i;
    }
    
    // SAFE - accessing within bounds
    values[0] = 1;
    values[50] = 2;
    values[99] = 3;
}

// ============================================================
// SECTION 5: Memory Leaks - SHOULD be flagged
// ============================================================

void memory_leak_no_free() {
    char *data = malloc(1024);
    
    // UNSAFE - allocated memory never freed
    if (data == NULL) {
        return;
    }
    
    strcpy(data, "Some data");
    // Missing free(data)
}

void memory_leak_early_return() {
    int *numbers = malloc(100 * sizeof(int));
    
    if (numbers == NULL) {
        return;
    }
    
    // Do some work
    for (int i = 0; i < 100; i++) {
        numbers[i] = i;
        
        if (i == 50) {
            // UNSAFE - early return without freeing
            return;
        }
    }
    
    free(numbers);
}

void correct_memory_management() {
    char *buffer = malloc(512);
    
    if (buffer == NULL) {
        return;
    }
    
    strcpy(buffer, "Data");
    
    // SAFE - properly freed
    free(buffer);
}

// ============================================================
// SECTION 6: Use After Free - SHOULD be flagged
// ============================================================

void use_after_free_bug() {
    char *ptr = malloc(100);
    strcpy(ptr, "Hello");
    
    free(ptr);
    
    // UNSAFE - using pointer after free
    printf("%s\n", ptr);
    strcpy(ptr, "World");
}

void double_free_bug() {
    int *data = malloc(sizeof(int) * 10);
    
    free(data);
    // UNSAFE - freeing same pointer twice
    free(data);
}

void safe_pointer_usage() {
    char *ptr = malloc(50);
    strcpy(ptr, "Test");
    free(ptr);
    
    // SAFE - reallocating after free
    ptr = malloc(50);
    strcpy(ptr, "New data");
    free(ptr);
}

// ============================================================
// SECTION 7: Null Pointer Dereference - SHOULD be flagged
// ============================================================

void null_pointer_deref_no_check() {
    char *buffer = malloc(256);
    
    // UNSAFE - no NULL check before use
    strcpy(buffer, "Data");
    buffer[0] = 'X';
}

void null_pointer_safe() {
    char *buffer = malloc(256);
    
    // SAFE - checking for NULL
    if (buffer != NULL) {
        strcpy(buffer, "Data");
        free(buffer);
    }
}

// ============================================================
// SECTION 8: Format String Vulnerabilities - SHOULD be flagged
// ============================================================

void format_string_vuln(char *user_input) {
    // UNSAFE - user input directly as format string
    printf(user_input);
    fprintf(stderr, user_input);
}

void safe_format_string(char *user_input) {
    // SAFE - proper format specifier
    printf("%s", user_input);
    fprintf(stderr, "%s\n", user_input);
}

// ============================================================
// SECTION 9: gets() - SHOULD ALWAYS be flagged
// ============================================================

void extremely_dangerous_gets() {
    char buffer[50];
    
    // CRITICAL - gets() has no bounds checking at all
    gets(buffer);
}

void safe_input_alternative() {
    char buffer[50];
    
    // SAFE - fgets with size limit
    if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
        buffer[strcspn(buffer, "\n")] = '\0';
    }
}

// ============================================================
// SECTION 10: sprintf vs snprintf
// ============================================================

void unsafe_sprintf() {
    char dest[20];
    int value = 12345;
    
    // UNSAFE - no bounds checking
    sprintf(dest, "Value: %d", value);
}

void safe_snprintf() {
    char dest[20];
    int value = 12345;
    
    // SAFE - bounded sprintf
    snprintf(dest, sizeof(dest), "Value: %d", value);
}

// ============================================================
// SECTION 11: Complex Real-World Scenarios
// ============================================================

void process_user_data(const char *username, const char *password) {
    User user;
    
    // SAFE if username/password are short enough
    strcpy(user.name, "DefaultUser");
    
    // UNSAFE - copying unknown-length strings
    strcpy(user.email, username);
}

int initialize_leaderboard() {
    typedef struct {
        int score;
        char name[20];
    } LeaderboardEntry;
    
    LeaderboardEntry board[10];
    
    // SAFE - initializing with literals that fit
    for (int i = 0; i < 10; i++) {
        board[i].score = 0;
        strcpy(board[i].name, "Anonymous");  // 10 bytes into 20
    }
    
    return 0;
}

void mixed_safety_function() {
    char safe_buf[100];
    char unsafe_buf[10];
    char *dynamic = malloc(50);
    
    // SAFE operations
    strcpy(safe_buf, "Short");
    
    // UNSAFE operations
    strcpy(unsafe_buf, "This is way too long");
    
    // Check before use
    if (dynamic != NULL) {
        strcpy(dynamic, "Data");
        free(dynamic);
    }
}

// ============================================================
// Main function for completeness
// ============================================================

int main(int argc, char *argv[]) {
    printf("Vulnerability Scanner Test Code\n");
    printf("This file tests various security issues\n");
    
    return 0;
}
