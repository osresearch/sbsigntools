

#include <stdint.h>
#include <openssl/asn1t.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>

#include <ccan/talloc/talloc.h>

#include "idc.h"

typedef struct idc_type_value {
	ASN1_OBJECT		*type;
	ASN1_TYPE		*value;
} IDC_TYPE_VALUE;

ASN1_SEQUENCE(IDC_TYPE_VALUE) = {
	ASN1_SIMPLE(IDC_TYPE_VALUE, type, ASN1_OBJECT),
	ASN1_OPT(IDC_TYPE_VALUE, value, ASN1_ANY),
} ASN1_SEQUENCE_END(IDC_TYPE_VALUE);

IMPLEMENT_ASN1_FUNCTIONS(IDC_TYPE_VALUE);

typedef struct idc_string {
	int type;
	union {
		ASN1_BMPSTRING	*unicode;
		ASN1_IA5STRING	*ascii;
	} value;
} IDC_STRING;

ASN1_CHOICE(IDC_STRING) = {
	ASN1_IMP(IDC_STRING, value.unicode, ASN1_BMPSTRING, 0),
	ASN1_IMP(IDC_STRING, value.ascii, ASN1_IA5STRING, 1),
} ASN1_CHOICE_END(IDC_STRING);

IMPLEMENT_ASN1_FUNCTIONS(IDC_STRING);

typedef struct idc_link {
	int type;
	union {
		ASN1_NULL	*url;
		ASN1_NULL	*moniker;
		IDC_STRING	*file;
	} value;
} IDC_LINK;

ASN1_CHOICE(IDC_LINK) = {
	ASN1_IMP(IDC_LINK, value.url, ASN1_NULL, 0),
	ASN1_IMP(IDC_LINK, value.moniker, ASN1_NULL, 1),
	ASN1_EXP(IDC_LINK, value.file, IDC_STRING, 2),
} ASN1_CHOICE_END(IDC_LINK);

IMPLEMENT_ASN1_FUNCTIONS(IDC_LINK);

typedef struct idc_pe_image_data {
        ASN1_BIT_STRING		*flags;
        IDC_LINK		*file;
} IDC_PEID;

ASN1_SEQUENCE(IDC_PEID) = {
        ASN1_SIMPLE(IDC_PEID, flags, ASN1_BIT_STRING),
        ASN1_EXP(IDC_PEID, file, IDC_LINK, 0),
} ASN1_SEQUENCE_END(IDC_PEID);

IMPLEMENT_ASN1_FUNCTIONS(IDC_PEID);

typedef struct idc_digest {
        X509_ALGOR              *alg;
        ASN1_OCTET_STRING       *digest;
} IDC_DIGEST;

ASN1_SEQUENCE(IDC_DIGEST) = {
        ASN1_SIMPLE(IDC_DIGEST, alg, X509_ALGOR),
        ASN1_SIMPLE(IDC_DIGEST, digest, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(IDC_DIGEST)

IMPLEMENT_ASN1_FUNCTIONS(IDC_DIGEST)

typedef struct idc {
        IDC_TYPE_VALUE  *data;
        IDC_DIGEST      *digest;
} IDC;

ASN1_SEQUENCE(IDC) = {
        ASN1_SIMPLE(IDC, data, IDC_TYPE_VALUE),
        ASN1_SIMPLE(IDC, digest, IDC_DIGEST),
} ASN1_SEQUENCE_END(IDC)

IMPLEMENT_ASN1_FUNCTIONS(IDC)

static int type_set_sequence(void *ctx, ASN1_TYPE *type,
		void *s, const ASN1_ITEM *it)
{
	uint8_t *seq_data, *tmp;
	ASN1_OCTET_STRING *os;
	ASN1_STRING *seq = s;
	int len;

	os = ASN1_STRING_new();

	len = ASN1_item_i2d((ASN1_VALUE *)seq, NULL, it);
	tmp = seq_data = talloc_array(ctx, uint8_t, len);
	ASN1_item_i2d((ASN1_VALUE *)seq, &tmp, it);

	ASN1_STRING_set(os, seq_data, len);
	ASN1_TYPE_set(type, V_ASN1_SEQUENCE, os);
	return 0;
}

const char obsolete[] = {
	0x00, 0x3c, 0x00, 0x3c, 0x00, 0x3c, 0x00, 0x4f, 0x00, 0x62,
	0x00, 0x73, 0x00, 0x6f, 0x00, 0x6c, 0x00, 0x65, 0x00, 0x74,
	0x00, 0x65, 0x00, 0x3e, 0x00, 0x3e, 0x00, 0x3e
};

int IDC_set(PKCS7 *p7, PKCS7_SIGNER_INFO *si, struct image *image)
{
	uint8_t *buf, *tmp, sha[SHA256_DIGEST_LENGTH];
	int idc_nid, peid_nid, len, rc;
	IDC_PEID *peid;
	ASN1_STRING *s;
	ASN1_TYPE *t;
	BIO *sigbio;
	IDC *idc;

	idc_nid = OBJ_create("1.3.6.1.4.1.311.2.1.4",
			"spcIndirectDataContext",
			"Indirect Data Context");
	peid_nid = OBJ_create("1.3.6.1.4.1.311.2.1.15",
			"spcPEImageData",
			"PE Image Data");

	image_hash_sha256(image, sha);

	idc = IDC_new();
	peid = IDC_PEID_new();

	peid->file = IDC_LINK_new();
	peid->file->type = 2;
	peid->file->value.file = IDC_STRING_new();
	peid->file->value.file->type = 0;
	peid->file->value.file->value.unicode = ASN1_STRING_new();
	ASN1_STRING_set(peid->file->value.file->value.unicode,
			obsolete, sizeof(obsolete));

	idc->data->type = OBJ_nid2obj(peid_nid);
	idc->data->value = ASN1_TYPE_new();
	type_set_sequence(NULL, idc->data->value, peid, &IDC_PEID_it);

        idc->digest->alg->parameter = ASN1_TYPE_new();
        idc->digest->alg->algorithm = OBJ_nid2obj(NID_sha256);
        idc->digest->alg->parameter->type = V_ASN1_NULL;
        ASN1_OCTET_STRING_set(idc->digest->digest, sha, sizeof(sha));

	len = i2d_IDC(idc, NULL);
	tmp = buf = talloc_array(NULL, uint8_t, len);
	i2d_IDC(idc, &tmp);

	/* Add the contentType authenticated attribute */
	PKCS7_add_signed_attribute(si, NID_pkcs9_contentType, V_ASN1_OBJECT,
						OBJ_nid2obj(idc_nid));

	/* Because the PKCS7 lib has a hard time dealing with non-standard
	 * data types, we create a temporary BIO to hold the signed data, so
	 * that the top-level PKCS7 object calculates the correct hash...
	 */
	sigbio = PKCS7_dataInit(p7, NULL);
	BIO_write(sigbio, buf+2, len-2);

	/* ... then we finalise the p7 content, which does the actual
	 * signing ... */
	rc = PKCS7_dataFinal(p7, sigbio);
	if (!rc) {
		fprintf(stderr, "dataFinal failed\n");
		ERR_print_errors_fp(stderr);
		return -1;
	}

	/* ... and we replace the content with the actual IDC ASN type. */
	t = ASN1_TYPE_new();
	s = ASN1_STRING_new();
	ASN1_STRING_set(s, buf, len);
	ASN1_TYPE_set(t, V_ASN1_SEQUENCE, s);
	PKCS7_set0_type_other(p7->d.sign->contents, idc_nid, t);

	return 0;
}


