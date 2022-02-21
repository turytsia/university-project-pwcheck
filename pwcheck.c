#include <stdio.h>
#include <stdlib.h>

//includes custom boolean type
typedef int bool;
#define true 1
#define false 0

//constants
#define MAX_LENGTH 100
#define MAX_CHAR 127
#define STATS "--stats"
#define FLAG_LEVEL "-l"
#define FLAG_PARAM "-p"

//extra functions
#define isDigit(ch) (ch >= '0' && ch <= '9')
#define isUpperCase(ch) (ch >= 'A' && ch <= 'Z')
#define isLowerCase(ch) (ch >= 'a' && ch <= 'z')
#define parseString(x) strtoull(x, NULL, 10)
//custom error handler
#define throw(error)                       \
    {                                      \
        fprintf(stderr, "Error: " #error); \
        return EXIT_FAILURE;               \
    }

//each element of this array will represent security level
//for instance, calling the first element as a function
//will check if the password matches the first security level
typedef bool (*SecurityLevel)(char *); //it allows us to get all the functions into an array (leaving details)
typedef unsigned long long U_LONG;     //short

//global vars
int LEVEL = 0, PARAM = 0;
bool isStats = false;

//--------    Prototypes     --------
bool SecurityLevelOne(char *password);
bool SecurityLevelTwo(char *password);
bool SecurityLevelThree(char *password);
bool SecurityLevelFour(char *password);

int strlength(char *str);
bool hasChar(char *str);
bool compare(char *str1, char *str2);
bool readArguments(int argc, char **argv);
bool statsValidation(int argc, char **argv);

int main(int argc, char **argv)
{
    //variables for passwords
    char password[MAX_LENGTH]; //array with passwords
    char c;                    //variable for characters from stdin
    int w_size = 0;            //password's length

    //variables for stats
    float avg = 0;
    int pass_count = 0;
    int min = MAX_LENGTH;
    int dif_count = 0;
    int dif[MAX_CHAR] = {0};

    //Array of functions (links)
    const SecurityLevel Protector[] = {
        &SecurityLevelOne,
        &SecurityLevelTwo,
        &SecurityLevelThree,
        &SecurityLevelFour};
    
    //validates arguments and stats
    if ((!statsValidation(argc, argv)) || !readArguments(argc, argv))
        throw(Invalid arguments.);

    //--------    Start     --------
    while ((c = getchar()) != EOF)
    {
        if ((password[w_size] = c) != '\n')
        {
            //validation
            if (++w_size > MAX_LENGTH)
                throw(Invalid password.);
            //stats check
            dif[(int)c] = 1;
        }
        else
        {
            //defines password's end
            password[w_size] = 0;

            //each security function returns true if password is OK for defined security level
            if (Protector[LEVEL - 1](password))
                printf("%s\n", password);

            //Password's length
            const int passwordLength = strlength(password);

            //stats check
            avg += passwordLength;
            if (min >= passwordLength)
                min = passwordLength;
            pass_count++;
            //refresh size for the next iteration
            w_size = 0;
        }
    }
    //Sum of various symbols that were used in Passwords
    for (int i = 0; i < MAX_CHAR; i++)
        dif_count += dif[i];

    if (isStats)
        printf("Statistika:\nRuznych znaku: %d\nMinimalni delka: %d\nPrumerna delka: %.1f\n", dif_count, min, avg / pass_count);

    return EXIT_SUCCESS;
    //--------                   --------
}
//bonus functionality
bool readArguments(int argc, char **argv)
{
    //error if there is more than 6 arguments
    if (argc > 6 || argc < 3)
        return false;
    //if stats presents we don't need to count it as an argument when looking for param and level
    argc -= isStats;
    //starts from the first passed argument
    for (int i = 1; i < argc;)
    {
        if (compare(argv[i], FLAG_LEVEL)) //if flag was found
        {
            if (++i >= argc) //checks if it's the last argument
            {
                LEVEL = 1;
                return true;
            }                                                           //if it's not
            LEVEL = compare(argv[i], FLAG_PARAM) ? 1 : atoi(argv[i++]); //gets info about the next argument
            if (LEVEL < 1 || LEVEL > 4)                                 //if it's one more flag then LEVEL = 1, if it's not means that there is a value for LEVEL
                return false;
            continue;
        }
        if (compare(argv[i], FLAG_PARAM)) //the same thing here
        {
            if (++i >= argc)
            {
                PARAM = 1;
                return true;
            }
            PARAM = compare(argv[i], FLAG_LEVEL) ? 1 : atoi(argv[i++]);
            continue;
        }
        //if the code got here
        //the value in argv will be a level or a parameter
        if (hasChar(argv[i]))
            return false;

        if (!LEVEL)
        {
            LEVEL = atoi(argv[i]);
            if (LEVEL < 1 || LEVEL > 4)
                return false;
        }
        else if (!PARAM)
        {
            U_LONG tempParam = parseString(argv[i]); //for the case when param is too big
            if (!tempParam)
                return false;
            PARAM = tempParam > MAX_LENGTH ? MAX_LENGTH : tempParam; //no point to check param > 100 because of limitations of password length
        }
        else
            return false;
        i++;
    }

    if (!PARAM || !LEVEL)// if user's set invalid arguments
        return false;

    return true;
}
//validates 3-rd argument
bool statsValidation(int argc, char **argv)
{
    int i = 0; //the position of the --stats in argv
    for (; i < argc; i++)
        if ((isStats = compare(argv[i], STATS)))
            break;
    if (isStats)
        return i == argc - 1;
    for (int i = 1; i < argc; i++) //verifies whether arguments have wrong spelling
        for (int j = 0; j < argv[i][j]; j++)
            if (!isDigit(argv[i][j]) && argv[i][j] != 'p' && argv[i][j] != 'l' && argv[i][j] != '-')
                return false;
    return true;
}

bool SecurityLevelOne(char *password)
{
    bool conditions[2] = {0};
    for (int i = 0; password[i]; i++)
    {
        if (!conditions[0]) //if character in password is uppercase
            conditions[0] = isUpperCase(password[i]);
        if (!conditions[1]) //if character in password is lowercase
            conditions[1] = isLowerCase(password[i]);

        if (conditions[0] && conditions[1]) //if conditions are true tat means the password is OK for 1 level
            return true;
    }
    return false; //if conditions are false or at least one of them
}

bool SecurityLevelTwo(char *password)
{
    if (SecurityLevelOne(password)) //checks if previous level is fulfilled.
    {
        bool conditions[2] = {0};
        //if parameter is < 3, it means first 2 options are valid because of the first security level
        if (PARAM < 3)
            return true;
        for (int i = 0; password[i]; i++)
        {
            if (!conditions[0] && isDigit(password[i])) //if password has numbers 0 - 9
            {
                conditions[0] = true;
            }
            else if (!conditions[1] && (password[i] >= 32 || password[i] < MAX_CHAR) && !isUpperCase(password[i]) && !isLowerCase(password[i]) && !isDigit(password[i]))
            {
                conditions[1] = true;
            }
            //if password has other symbols ^

            if (PARAM >= 4 ? conditions[0] && conditions[1] : conditions[0] || conditions[1])
                return true;
        }
    }
    return false;
}

bool SecurityLevelThree(char *password)
{
    if (SecurityLevelTwo(password))
    {
        int counter = 1;
        //if parameter is greater than password's length, accept this password
        if (PARAM >= strlength(password))
            return true;

        for (int i = 1; password[i]; i++)
            if ((counter = password[i - 1] == password[i] ? counter + 1 : 1) >= PARAM) //when counter >= PARAM then we return false
                return false;
        return true;
    }
    return false;
}

bool SecurityLevelFour(char *password)
{
    if (SecurityLevelThree(password))
    {
        const int passwordLength = strlength(password);
        char substr[MAX_LENGTH][MAX_LENGTH] = {0}; // temp substring
        int substrlengthgth = 0;                   //substring counter
        if (PARAM >= passwordLength)
            return true;
        for (; password[substrlengthgth] && PARAM + substrlengthgth <= passwordLength; substrlengthgth++)
            for (int j = substrlengthgth; j < PARAM + substrlengthgth; j++) //with each iteration cuts new substring
                substr[substrlengthgth][j - substrlengthgth] = password[j]; //new substring will be saved in the array of substrings
        for (int i = 1; i < substrlengthgth; i++)
            for (int j = i; j < substrlengthgth; j++)
                if (compare(substr[i - 1], substr[j])) //compares each substring
                    return false;                      //returns false if it finds the same substring
        return true;
    }
    return false;
}

int strlength(char *str) //custom strlength
{
    int length = 0;
    while (str[length])
        length++;
    return length;
}

bool compare(char *str1, char *str2) //custom function to compare 2 strings
{
    if (strlength(str1) != strlength(str2))
        return false;

    for (int i = 0; str1[i]; i++)
        if (str1[i] != str2[i])
            return false;
    return true;
}

bool hasChar(char *str) //function to check if string has any other symbol but digit
{
    for (int i = 0; str[i]; i++)
        if (!isDigit(str[i]))
            return true;
    return false;
}
