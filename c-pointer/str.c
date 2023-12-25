#include <stdio.h>

char* test(char *d, const char *s)
{
	char *save = d;

	for (; *d != '\0'; ++d);
	while (*d++ = *s++);
	
	return save;
}

void test2(char *s)
{
	printf("%s\n", s+3);
}

void __strcpy(unsigned char *d, unsigned char *s, unsigned int size)
{
    while (size-- > 0)
        *d++ = *s++;
}

struct listener_key {
	unsigned short port;
    unsigned char protocol;
};

struct event_x {
    int direction;
    unsigned long lock;
} event;

int main()
{
	char x[] = "Hello";
	char y[] = "World";

	__strcpy(x, y, 5);
	printf("%s\n", x);

	char *z = x;
	printf("address of pointer: %p\n", (void*)&z);
	printf("address of value that pointer point to (value of variable z): %p\n", (void*)z);
	printf("address of value that pointer point to: %p\n", (void*)&x);
    printf("%s\n", test(x, y));

	test2(x);
	test2("11331322");
	printf("%c\n", *(x+1));
	printf("%c\n", *(z+1));
	printf("%c\n", *++z);
	printf("%c\n", *z);


	struct listener_key key;// = {};
    // __builtin_memset(&key, 0, sizeof(key))
    printf("sizeof(key) = %lu\n", sizeof(key));

	__builtin_memset(&event, 0, sizeof(event));
    printf("sizeof(event) = %lu\n", sizeof(event));

    return 0;
}