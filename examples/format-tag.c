#include <err.h>
#include <stdio.h>
#include <stdlib.h>

#include <nfc/nfc.h>
#include <nfc/nfc-types.h>
#include <freefare.h>

static unsigned char GK_DEFAULT_DESFIRE_KEY[8] = { 0x0 };

int main(int argc, const char *argv[]) {
    int retval = EXIT_SUCCESS;

    // Display libnfc version
    const char *acLibnfcVersion = nfc_version();
    printf("%s uses libnfc %s\n", argv[0], acLibnfcVersion);

    nfc_device *device = NULL;
    MifareTag *tags = NULL;
    MifareDESFireKey default_desfire_key = mifare_desfire_des_key_new(GK_DEFAULT_DESFIRE_KEY);

    nfc_connstring devices[8];
    size_t device_count;

    nfc_context *context;
    nfc_init(&context);

    if (context == NULL) {
        errx(EXIT_FAILURE, "Unable to init libnfc (malloc)");
    }

    device_count = nfc_list_devices(context, devices, sizeof(devices) / sizeof(*devices));
    if (device_count <= 0) {
        warnx("No NFC device found");
        retval = EXIT_FAILURE;
        goto abort;
    }

    if (!(device = nfc_open(context, devices[0]))) {
        warnx("nfc_open() failed.");
        retval = EXIT_FAILURE;
        goto abort;
    }

    if (!(tags = freefare_get_tags(device))) {
        warnx("Error listing tags.");
        retval = EXIT_FAILURE;
        goto abort_nfc;
    }

    for (size_t i = 0; tags[i]; i++) {
        MifareTag tag = tags[i];

        switch (freefare_get_tag_type(tag)) {
            case DESFIRE:
                break;
            default:
                continue;
        }

        char *tag_uid = freefare_get_tag_uid(tag);
        printf("Tag with UID %s is a %s\n", tag_uid, freefare_get_tag_friendly_name(tag));
        free(tag_uid);

        int r;

        r = mifare_desfire_connect(tag);
        if (r < 0) {
            warnx("format-tag: failed to connect to tag");
            goto abort_tags;
        }

        r = mifare_desfire_select_application(tag, NULL);
        if (r < 0) {
            warnx("format-tag: failed to select master application");
            goto abort_disconnect;
        }

        r = mifare_desfire_authenticate(tag, 0x0, default_desfire_key);
        if (r < 0) {
            warnx("format-tag: failed to authenticate to tag");
            goto abort_disconnect;
        }

        r = mifare_desfire_format_picc(tag);
        if (r < 0) {
            warnx("format-tag: failed to format tag");
            goto abort_disconnect;
        }

        mifare_desfire_disconnect(tag);
        printf("Successfully formatted tag!\n");

        abort_disconnect:
        mifare_desfire_disconnect(tag);
        goto abort_tags;
    }

    abort_tags:
    freefare_free_tags(tags);

    abort_nfc:
    nfc_close(device);

    abort:
    mifare_desfire_key_free(default_desfire_key);
    nfc_exit(context);
    exit(retval);
}