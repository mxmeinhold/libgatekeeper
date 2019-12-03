#include <err.h>
#include <stdio.h>
#include <stdlib.h>

#include <nfc/nfc.h>
#include <nfc/nfc-types.h>
#include <freefare.h>
#include <gatekeeper/gatekeeper.h>

int main(int argc, const char *argv[]) {
    int retval = EXIT_SUCCESS;

    // Display libnfc version
    const char *acLibnfcVersion = nfc_version();
    printf("%s uses libnfc %s\n", argv[0], acLibnfcVersion);

    nfc_device *device = NULL;
    MifareTag *tags = NULL;

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

        realm_t **realms = malloc(sizeof(realm_t *));
        realms[0] = realm_create(0, "Doors",
                "7c5d9984-8392-4dce-8dc1-75791fa6bf31",
                "c789aef4d156b9e1a23bcbe66742b4eb",
                "53e49fedce8a1fad6be924cb51f79bfe",
                "96e874711115cde3ca530c9a15c4838a",
                "-----BEGIN PUBLIC KEY-----\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEUSCSsyBgHLLs9d5+p+cTGljR9aeFZ19D\ngBkuomyNPEy2rYI/0g9jeftRkkRXlZNQG/jk8PNtKuYoq4cKTYnMiZEiIcHq6fRi\nusrdYdkrS2iau+xENfzkkouvYJwarMtu\n-----END PUBLIC KEY-----\n",
                "-----BEGIN EC PRIVATE KEY-----\nMIGkAgEBBDCYfNkZFFqtgPRwxWy3SWfNvznHO0V5CNOlysmE3jXOGtO/99XpmKx4\nAsPFrMm6iragBwYFK4EEACKhZANiAARRIJKzIGAcsuz13n6n5xMaWNH1p4VnX0OA\nGS6ibI08TLatgj/SD2N5+1GSRFeVk1Ab+OTw820q5iirhwpNicyJkSIhwerp9GK6\nyt1h2StLaJq77EQ1/OSSi69gnBqsy24=\n-----END EC PRIVATE KEY-----\n");

        if (realms[0] == NULL) {
            warnx("Failed to construct realm.");
            retval = EXIT_FAILURE;
            goto abort_tags;
        }

        retval = issue_tag(tag, "cdfc36ef1b3d87a81a4114cb75459e27", realms, 1);
        if(retval != 0) {
            warnx("Failed to issue tag.");
            retval = EXIT_FAILURE;
            goto abort_tags;
        }

        // Successfully issued tag
        warnx("Successfully issued tag!");

        if(authenticate_tag(tag, realms[0])) {
            warnx("Tag authenticates!");
        } else {
            warnx("Tag failed authentication.");
        }

        realm_free(realms[0]);
        free(realms);
    }

    abort_tags:
    freefare_free_tags(tags);

    abort_nfc:
    nfc_close(device);

    abort:
    nfc_exit(context);
    exit(retval);
}