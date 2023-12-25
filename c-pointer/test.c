#include <stdio.h>  
struct student  
{  
    // char *p;     /* 8 bytes */
    int x;      /* 8 bytes */
    char c;      /* 1 byte */

//    int c;  
} stud1;  

struct listener_key {
    unsigned char protocol;
    unsigned short port;
};

int main()  
{  
//    struct listener_key key; // variable declaration of the student type.. 
   __builtin_memset(&stud1, 0, sizeof(stud1)); 
   // Displaying the size of the structure student.  
//    printf("The size of the student structure is %d, %d, %d", sizeof(stud1), sizeof(stud1.direction), sizeof(stud1.lock));  
    printf("The size of the student structure is %d, %d, %d", sizeof(stud1), sizeof(stud1.x), sizeof(stud1.c));  
   return 0; 
}  