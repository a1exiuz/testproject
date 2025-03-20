#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE_LENGTH 300
#define MAX_ENTRIES 100
#define FILE_NAME "user_info.txt"  // Fixed filename

// Structure to hold incident data
typedef struct {
    char name[MAX_LINE_LENGTH];
    char supplies[MAX_LINE_LENGTH];
    char location[MAX_LINE_LENGTH];
    int num_people;
    int hours_stranded;
    int injuries;
    float severity_score;
} Incident;

// Function to normalize values (scale to 0 to 1 range)
float normalize(int value, int max_value) {
    return max_value > 0 ? (float)value / max_value : 0;
}

// Function to calculate severity score
float calculateSeverityScore(int num_people, int hours_stranded, int injuries) {
    int max_people = 100;
    int max_hours = 72;
    int max_injuries = 20;

    float weight_people = 0.3f;
    float weight_hours = 0.4f;
    float weight_injuries = 0.3f;

    float norm_people = normalize(num_people, max_people);
    float norm_hours = normalize(hours_stranded, max_hours);
    float norm_injuries = normalize(injuries, max_injuries);

    return (weight_people * norm_people) +
        (weight_hours * norm_hours) +
        (weight_injuries * norm_injuries);
}

// Function to classify severity level
const char* getSeverity(float score) {
    if (score < 0.4) return "Low";
    else if (score < 0.7) return "Medium";
    return "High";
}

// Function to read incidents from file
int processFile(Incident incidents[]) {
    FILE* file =NULL;
    errno_t err = fopen_s(&file, FILE_NAME, "r");
    if (err != 0 || file == NULL) {
        perror("Error opening file");
        printf("Make sure the file '%s' exists in the program's directory.\n", FILE_NAME);
        return -1;
    }

    char line[MAX_LINE_LENGTH];
    int count = 0;

    while (fgets(line, sizeof(line), file) && count < MAX_ENTRIES) {
        if (strncmp(line, "Name:", 5) == 0) {
            sscanf_s(line, "Name: %[^\n]", incidents[count].name, (unsigned)_countof(incidents[count].name));

        }
        else if (strncmp(line, "Supplies Needed:", 16) == 0) {
            sscanf_s(line, "Supplies Needed: %[^\n]", incidents[count].supplies, (unsigned)_countof(incidents[count].supplies));

        }
        else if (strncmp(line, "Number of People:", 17) == 0) {
            if (sscanf_s(line, "Number of People: %d", &incidents[count].num_people) != 1) {
                printf("Warning: Missing 'Number of People' in entry %d. Defaulting to 0.\n", count + 1);
                incidents[count].num_people = 0;
            }
        }
        else if (strncmp(line, "Hours Stranded:", 15) == 0) {
            if (sscanf_s(line, "Hours Stranded: %d", &incidents[count].hours_stranded) != 1) {
                printf("Warning: Missing 'Hours Stranded' in entry %d. Defaulting to 0.\n", count + 1);
                incidents[count].hours_stranded = 0;
            }
        }
        else if (strncmp(line, "Location:", 9) == 0) {
            sscanf_s(line, "Location: %[^\n]", incidents[count].location, (unsigned)_countof(incidents[count].supplies));
        }
        else if (strncmp(line, "Number of Injuries:", 19) == 0) {
            if (sscanf_s(line, "Number of Injuries: %d", &incidents[count].injuries) != 1) {
                printf("Warning: Missing 'Number of Injuries' in entry %d. Defaulting to 0.\n", count + 1);
                incidents[count].injuries = 0;
            }

            // Calculate severity score for this incident
            incidents[count].severity_score = calculateSeverityScore(
                incidents[count].num_people,
                incidents[count].hours_stranded,
                incidents[count].injuries
            );

            // Move to the next incident
            count++;
        }
    }

    fclose(file);
    return count;  // Number of incidents processed
}

// Function to compare incidents by severity for sorting
int compareIncidents(const void* a, const void* b) {
    float scoreA = ((Incident*)a)->severity_score;
    float scoreB = ((Incident*)b)->severity_score;
    return (scoreA < scoreB) - (scoreA > scoreB);  // Descending order
}

// Function to print sorted incidents
void printIncidents(Incident incidents[], int count) {
    qsort(incidents, count, sizeof(Incident), compareIncidents);

    printf("\n===== Sorted Incident Reports by Severity =====\n");
    for (int i = 0; i < count; i++) {
        const char* severity = getSeverity(incidents[i].severity_score);
        printf("\nIncident #%d\n", i + 1);
        printf("Name: %s\n", incidents[i].name);
        printf("Supplies Needed: %s\n", incidents[i].supplies);
        printf("Number of People: %d\n", incidents[i].num_people);
        printf("Hours Stranded: %d\n", incidents[i].hours_stranded);
        printf("Location: %s\n", incidents[i].location);
        printf("Number of Injuries: %d\n", incidents[i].injuries);
        printf("Severity Score: %.2f (%s)\n", incidents[i].severity_score, severity);
        printf("-----------------------------------------\n");
    }
}

// Main function: Reads file, processes data, sorts, and prints results
int main() {
    Incident incidents[MAX_ENTRIES];

    int count = processFile(incidents);
    if (count > 0) {
        printIncidents(incidents, count);
    }
    else {
        printf("No valid incidents found in '%s'.\n", FILE_NAME);
    }

    return 0;
}
