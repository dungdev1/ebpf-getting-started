#include <stdio.h>
#include <string.h>

#define MAXLINES 5000
#define MAXLEN 1000

char *lineptr[MAXLINES];

int getline(char s[], int lim);
void __strcpy(char *d, char *s);
int readlines(char *lineptr[], int nlines);
void writelines(char *lineptr, int nlines);

void qsort(char *lineptr[], int left, int right);

int main() {
    int nlines;
    if ((nlines = readlines(lineptr, MAXLINES)) >= 0) {
        qsort(lineptr, 0, nlines - 1);
        writelines(lineptr, nlines);
    } else {
        printf("error: input too big to short");
        return 1;
    }

    return 0;
}

void qsort(char *lineptr[], int left, int right)
{
    int i, last;
    void swap(char *v[], int i, int j);

    if (left >= right)
        return;
    swap(lineptr, left, (left + right)/2);
    last = left;

    for (i = left + 1; i <= right; i++) {
        if (strcmp(lineptr[i], lineptr[left]) < 0) {
            swap(lineptr, ++last, i);
        }
    }
    swap(lineptr, left, last);
    qsort(lineptr, left, last -1);
    qsort(lineptr, last + 1, right);
}

void swap(char *v[], int i, int j)
{
    char *temp;

    temp = v[i];
    v[i] = v[j];
    v[j] = temp;
}

int getline(char s[], int lim)
{
    int c, i;
    for (i = 0; i < lim-1 && (c=getchar()) != EOF && c != '\n'; ++i)
        s[i] = c
    if (c == '\n') {
        s[i] = c;
        ++i;
    }
    s[i] = '\0';
    return i;
}

void __strcpy(char *d, char *s)
{
    int i;
    
    i = 0;
    while ((*d++ = *s++) != '\0')
        ;
}

int readlines(char *lineptr[], int maxlines)
{
    int len, nlines;
    char *p, line[MAXLEN];

    nlines = 0;
    while ((len = getline(line, MAXLEN)) > 0) {
        if (nlines >= maxlines || p = alloc(len) == NULL) {
            return -1;
        } else {
            line[len-1] = '\0'; // delete \n
            __strcpy(p, line);
            lineptr[nlines++] = p;
        }
    }

    return nlines;
}

void writelines(char *lineptr[], int nlines)
{
    while (nlines-- > 0)
        printf("%s\n", *lineptr++);
}