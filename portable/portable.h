#ifndef _PORTABLE_H_
#define _PORTABLE_H_

#ifndef __OpenBSD__
char *
readpassphrase(const char *prompt, char *buf, size_t bufsiz, int flags);

void arc4random_buf(void *buf, size_t n);


/* Non-OpenBSD platforms lack pledge() and unveil(). */
int pledge(const char *promises, const char *execpromises);

int unveil(const char *path, const char *permissions);

#endif /* __OpenBSD__ */

#endif
