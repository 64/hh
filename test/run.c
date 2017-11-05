#include <hh.h>

int main(void) {
	int fd;
	if ((fd = hh_init()) < 0)
		return -1;
	if (hh_listen(fd) != 0)
		return -1;
	if (hh_cleanup(fd) != 0)
		return -1;
	return 0;
}
