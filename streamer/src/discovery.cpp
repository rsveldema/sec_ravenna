#include <inttypes.h>
#include <avahi-common/cdecl.h>
#include <avahi-common/address.h>
#include <avahi-common/strlst.h>
#include <avahi-common/defs.h>
#include <avahi-common/watch.h>
#include <avahi-common/gccmacro.h>

#include <avahi-client/client.h>
#include <avahi-client/publish.h>

#include <avahi-common/alternative.h>
#include <avahi-common/simple-watch.h>
#include <avahi-common/malloc.h>
#include <avahi-common/error.h>
#include <avahi-common/timeval.h>

#include <discovery.hpp>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

static AvahiSimplePoll *simple_poll = nullptr;
static char *name;
static AvahiEntryGroup *group = NULL;

static void create_services(AvahiClient *c);

static void entry_group_callback(AvahiEntryGroup *g,
                                 AvahiEntryGroupState state,
                                 AVAHI_GCC_UNUSED void *userdata)
{
    assert(g == group || group == nullptr);
    group = g;

    /* Called whenever the entry group state changes */

    switch (state)
    {
    case AVAHI_ENTRY_GROUP_ESTABLISHED:
        /* The entry group has been established successfully */
        fprintf(stderr, "Service '%s' successfully established.\n", name);
        break;

    case AVAHI_ENTRY_GROUP_COLLISION:
    {
        /* A service name collision with a remote service
         * happened. Let's pick a new name */
        auto *n = avahi_alternative_service_name(name);
        avahi_free(name);
        name = n;

        fprintf(stderr, "Service name collision, renaming service to '%s'\n", name);

        /* And recreate the services */
        create_services(avahi_entry_group_get_client(g));
        break;
    }

    case AVAHI_ENTRY_GROUP_FAILURE:

        fprintf(stderr, "Entry group failure: %s\n", avahi_strerror(avahi_client_errno(avahi_entry_group_get_client(g))));

        /* Some kind of failure happened while we were registering our services */
        avahi_simple_poll_quit(simple_poll);
        break;

    case AVAHI_ENTRY_GROUP_UNCOMMITED:
    case AVAHI_ENTRY_GROUP_REGISTERING:;
    }
}

static void create_services(AvahiClient *c)
{
    char *n, r[128];
    int ret;
    assert(c);

    /* If this is the first time we're called, let's create a new
     * entry group if necessary */

    if (!group)
        if (!(group = avahi_entry_group_new(c, entry_group_callback, nullptr)))
        {
            fprintf(stderr, "avahi_entry_group_new() failed: %s\n", avahi_strerror(avahi_client_errno(c)));
            goto fail;
        }

    /* If the group is empty (either because it was just created, or
     * because it was reset previously, add our entries.  */

    if (avahi_entry_group_is_empty(group))
    {
        fprintf(stderr, "Adding service '%s'\n", name);

        /* Create some random TXT data */
        snprintf(r, sizeof(r), "random=%i", rand());

        /* We will now add two services and one subtype to the entry
         * group. The two services have the same name, but differ in
         * the service type (IPP vs. BSD LPR). Only services with the
         * same name should be put in the same entry group. */

        /* Add the service for IPP */
        if ((ret = avahi_entry_group_add_service(group,
                                                 AVAHI_IF_UNSPEC,
                                                 AVAHI_PROTO_UNSPEC,
                                                 (AvahiPublishFlags)0,
                                                 name,
                                                 "_ipp._tcp",
                                                 nullptr, nullptr, 651,
                                                 "test=blah",
                                                 r,
                                                 nullptr)) < 0)
        {

            if (ret == AVAHI_ERR_COLLISION)
                goto collision;

            fprintf(stderr, "Failed to add _ipp._tcp service: %s\n", avahi_strerror(ret));
            goto fail;
        }

        /* Add the same service for BSD LPR */
        if ((ret = avahi_entry_group_add_service(group,
                        AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC,
                        (AvahiPublishFlags) 0,
                        name, "_printer._tcp",
                        nullptr,
                        nullptr,
                        515,
                        nullptr)) < 0)
        {

            if (ret == AVAHI_ERR_COLLISION)
                goto collision;

            fprintf(stderr, "Failed to add _printer._tcp service: %s\n", avahi_strerror(ret));
            goto fail;
        }

        /* Add an additional (hypothetic) subtype */
        if ((ret = avahi_entry_group_add_service_subtype(group,
                                                         AVAHI_IF_UNSPEC,
                                                         AVAHI_PROTO_UNSPEC,
                                                         (AvahiPublishFlags)0,
                                                         name,
                                                         "_printer._tcp",
                                                         nullptr,
                                                         "_magic._sub._printer._tcp") < 0))
        {
            fprintf(stderr, "Failed to add subtype _magic._sub._printer._tcp: %s\n", avahi_strerror(ret));
            goto fail;
        }

        /* Tell the server to register the service */
        if ((ret = avahi_entry_group_commit(group)) < 0)
        {
            fprintf(stderr, "Failed to commit entry group: %s\n", avahi_strerror(ret));
            goto fail;
        }
    }

    return;

collision:

    /* A service name collision with a local service happened. Let's
     * pick a new name */
    n = avahi_alternative_service_name(name);
    avahi_free(name);
    name = n;

    fprintf(stderr, "Service name collision, renaming service to '%s'\n", name);

    avahi_entry_group_reset(group);

    create_services(c);
    return;

fail:
    avahi_simple_poll_quit(simple_poll);
}

static void client_callback(AvahiClient *c, AvahiClientState state, AVAHI_GCC_UNUSED void *userdata)
{
    assert(c);

    /* Called whenever the client or server state changes */

    switch (state)
    {
    case AVAHI_CLIENT_S_RUNNING:

        /* The server has startup successfully and registered its host
         * name on the network, so it's time to create our services */
        create_services(c);
        break;

    case AVAHI_CLIENT_FAILURE:

        fprintf(stderr, "Client failure: %s\n", avahi_strerror(avahi_client_errno(c)));
        avahi_simple_poll_quit(simple_poll);

        break;

    case AVAHI_CLIENT_S_COLLISION:

        /* Let's drop our registered services. When the server is back
         * in AVAHI_SERVER_RUNNING state we will register them
         * again with the new host name. */

    case AVAHI_CLIENT_S_REGISTERING:

        /* The server records are now being established. This
         * might be caused by a host name change. We need to wait
         * for our own records to register until the host name is
         * properly esatblished. */

        if (group)
            avahi_entry_group_reset(group);

        break;

    case AVAHI_CLIENT_CONNECTING:;
    }
}

void Discovery::publish()
{

    /* Allocate main loop object */
    if (!(simple_poll = avahi_simple_poll_new()))
    {
        fprintf(stderr, "Failed to create simple poll object.\n");
        return;
    }

    name = avahi_strdup("MegaPrinter");

    AvahiClient *avahi_client_new(
        const AvahiPoll *poll_api /**< The abstract event loop API to use */,
        AvahiClientFlags flags /**< Some flags to modify the behaviour of  the client library */,
        AvahiClientCallback callback /**< A callback that is called whenever the state of the client changes. This may be NULL. Please note that this function is called for the first time from within the avahi_client_new() context! Thus, in the callback you should not make use of global variables that are initialized only after your call to avahi_client_new(). A common mistake is to store the AvahiClient pointer returned by avahi_client_new() in a global variable and assume that this global variable already contains the valid pointer when the callback is called for the first time. A work-around for this is to always use the AvahiClient pointer passed to the callback function instead of the global pointer.  */,
        void *userdata /**< Some arbitrary user data pointer that will be passed to the callback function */,
        int *error /**< If creation of the client fails, this integer will contain the error cause. May be NULL if you aren't interested in the reason why avahi_client_new() failed. */);

    int error = 0;
    auto *poll_api = avahi_simple_poll_get(simple_poll);

    AvahiClient *client = avahi_client_new(poll_api,
                                           (AvahiClientFlags)0,
                                           client_callback,
                                           nullptr, &error);
}