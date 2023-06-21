#ifndef __OpenBSD__
/* Non-OpenBSD platforms lack pledge() and unveil(). */
int pledge(const char *promises, const char *execpromises)
{
  return 0;
}

int unveil(const char *path, const char *permissions) 
{
  return 0;
}
#endif /* __OpenBSD__ */
