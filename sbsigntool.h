#ifndef SBSIGNTOOL_H
#define SBSIGNTOOL_H

struct sign_context {
	struct image *image;
	const char *infilename;
	const char *outfilename;
	int verbose;
}

#endif /* SBSIGNTOOL_H */

