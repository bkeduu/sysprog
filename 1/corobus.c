#include "corobus.h"

#include "libcoro.h"
#include "rlist.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define INIT_CAPACITY 10
#define CAP_MULTIPLIER 2

struct data_vector {
	unsigned *data;
	size_t size;
	size_t capacity;
};

#if 1 /* Uncomment this if want to use */

/** Append @a count messages in @a data to the end of the vector. */
static void
data_vector_append_many(struct data_vector *vector,
	const unsigned *data, size_t count)
{
	if (vector->size + count > vector->capacity) {
		if (vector->capacity == 0)
			vector->capacity = 4;
		else
			vector->capacity *= 2;
		if (vector->capacity < vector->size + count)
			vector->capacity = vector->size + count;
		vector->data = realloc(vector->data,
			sizeof(vector->data[0]) * vector->capacity);
	}
	memcpy(&vector->data[vector->size], data, sizeof(data[0]) * count);
	vector->size += count;
}

/** Append a single message to the vector. */
static void
data_vector_append(struct data_vector *vector, unsigned data)
{
	data_vector_append_many(vector, &data, 1);
}

/** Pop @a count of messages into @a data from the head of the vector. */
static void
data_vector_pop_first_many(struct data_vector *vector, unsigned *data, size_t count)
{
	assert(count <= vector->size);
	memcpy(data, vector->data, sizeof(data[0]) * count);
	vector->size -= count;
	memmove(vector->data, &vector->data[count], vector->size * sizeof(vector->data[0]));
}

/** Pop a single message from the head of the vector. */
static unsigned
data_vector_pop_first(struct data_vector *vector)
{
	unsigned data = 0;
	data_vector_pop_first_many(vector, &data, 1);
	return data;
}

#endif

/**
 * One coroutine waiting to be woken up in a list of other
 * suspended coros.
 */
struct wakeup_entry {
	struct rlist base;
	struct coro *coro;
};

/** A queue of suspended coros waiting to be woken up. */
struct wakeup_queue {
	struct rlist coros;
};

#if 1 /* Uncomment this if want to use */

/** Suspend the current coroutine until it is woken up. */
static void
wakeup_queue_suspend_this(struct wakeup_queue *queue)
{
	struct wakeup_entry entry;
	entry.coro = coro_this();
	rlist_add_tail_entry(&queue->coros, &entry, base);
	coro_suspend();
	rlist_del_entry(&entry, base);
}

/** Wakeup the first coroutine in the queue. */
static struct wakeup_entry *
wakeup_queue_wakeup_first(struct wakeup_queue *queue)
{
	if (rlist_empty(&queue->coros))
		return NULL;
	struct wakeup_entry *entry = rlist_first_entry(&queue->coros,
		struct wakeup_entry, base);
	coro_wakeup(entry->coro);
	return entry;
}

static void
wakeup_queue_wakeup_delete_first(struct wakeup_queue *queue)
{
	struct wakeup_entry *entry = wakeup_queue_wakeup_first(queue);
	if (entry != NULL) {
		rlist_del_entry(entry, base);
	}
}

#endif

struct coro_bus_channel {
	/** Flag, that indicates that one of coros started closing the channel. */
	int about_to_close;
	/** Channel max capacity. */
	size_t size_limit;
	/** Coroutines waiting until the channel is not full. */
	struct wakeup_queue send_queue;
	/** Coroutines waiting until the channel is not empty. */
	struct wakeup_queue recv_queue;
	/** Message queue. */
	struct data_vector data;
};

struct coro_bus {
	struct coro_bus_channel **channels;
	size_t channel_count;
	size_t channel_capacity;
};

static enum coro_bus_error_code global_error = CORO_BUS_ERR_NONE;

enum coro_bus_error_code
coro_bus_errno(void)
{
	return global_error;
}

void
coro_bus_errno_set(enum coro_bus_error_code err)
{
	global_error = err;
}

static void
coro_bus_channel_free(struct coro_bus *bus, struct coro_bus_channel *chan);

static int
coro_bus_realloc_channels(struct coro_bus *bus);

static int
coro_bus_is_channel_send_blocking(struct coro_bus_channel *chan)
{
	assert(chan != NULL);
	return chan->size_limit == chan->data.size;
}

static int
coro_bus_is_channel_recv_blocking(struct coro_bus_channel *chan)
{
	assert(chan != NULL);
	return 0 == chan->data.size;
}

static struct coro_bus_channel *
coro_bus_find_channel(struct coro_bus *bus, int channel)
{
	assert(bus != NULL);
	return bus->channels[channel];
}

struct coro_bus *
coro_bus_new(void)
{
	struct coro_bus *bus = calloc(1, sizeof(struct coro_bus));
	if (bus == NULL) {
		coro_bus_errno_set(CORO_BUS_ERR_UNKNOWN);
		return NULL;
	}

	bus->channels = calloc(INIT_CAPACITY, sizeof(struct coro_bus_channel *));
	if (bus->channels == NULL) {
		free(bus);
		coro_bus_errno_set(CORO_BUS_ERR_UNKNOWN);
		return NULL;
	}

	bus->channel_capacity = INIT_CAPACITY;

	coro_bus_errno_set(CORO_BUS_ERR_NONE);
	return bus;
}

void
coro_bus_delete(struct coro_bus *bus)
{
	assert(bus != NULL);

	for (size_t i = 0; i < bus->channel_count; ++i) {
		if (bus->channels[i] != NULL) {
			coro_bus_channel_free(bus, bus->channels[i]);
		}
	}

	free(bus->channels);
	free(bus);
}

int
coro_bus_channel_open(struct coro_bus *bus, size_t size_limit)
{
	assert(bus != NULL);
	assert(size_limit != 0);

	coro_bus_realloc_channels(bus);

	struct coro_bus_channel *chan = calloc(1, sizeof(struct coro_bus_channel));
	if (chan == NULL) {
		coro_bus_errno_set(CORO_BUS_ERR_UNKNOWN);
		return -1;
	}

	chan->data.data = malloc(sizeof(unsigned) * size_limit);
	if (chan->data.data == NULL) {
		free(chan);
		coro_bus_errno_set(CORO_BUS_ERR_UNKNOWN);
		return -1;
	}

	chan->data.capacity = size_limit;
	chan->size_limit = size_limit;

	size_t desc = 0;
	for (; desc < bus->channel_count && bus->channels[desc] != NULL; ++desc) { }

	rlist_create(&chan->recv_queue.coros);
	rlist_create(&chan->send_queue.coros);

	bus->channels[desc] = chan;

	if (desc == bus->channel_count) {
		++bus->channel_count;
	}

	coro_bus_errno_set(CORO_BUS_ERR_NONE);
	return desc;
}

void
coro_bus_channel_close(struct coro_bus *bus, int channel)
{
	assert(bus != NULL);
	assert(channel >= 0);

	struct coro_bus_channel *chan = coro_bus_find_channel(bus, channel);
	if (chan == NULL) {
		return;
	}

	coro_bus_channel_free(bus, chan);
	bus->channels[channel] = NULL;

	coro_bus_realloc_channels(bus);
}

static void
coro_bus_channel_free(struct coro_bus *bus, struct coro_bus_channel *chan)
{
	assert(bus != NULL);
	assert(chan != NULL);

	chan->about_to_close = 1;

	while (!rlist_empty(&chan->recv_queue.coros)) {
		wakeup_queue_wakeup_delete_first(&chan->recv_queue);
	}

	while (!rlist_empty(&chan->send_queue.coros)) {
		wakeup_queue_wakeup_delete_first(&chan->send_queue);
	}

	free(chan->data.data);
	free(chan);
}

static void
coro_bus_send_internal(struct coro_bus_channel *chan, unsigned data)
{
	assert(chan != NULL);

	data_vector_append(&chan->data, data);
	wakeup_queue_wakeup_first(&chan->recv_queue);
}

int
coro_bus_send(struct coro_bus *bus, int channel, unsigned data)
{
	assert(bus != NULL);
	assert(channel >= 0);

	struct coro_bus_channel *chan = coro_bus_find_channel(bus, channel);
	if (chan == NULL) {
		coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);
		return -1;
	}

	while (chan->about_to_close == 0) {
		if (coro_bus_is_channel_send_blocking(chan)) {
			wakeup_queue_suspend_this(&chan->send_queue);
		}
		else {
			coro_bus_send_internal(chan, data);
			coro_bus_errno_set(CORO_BUS_ERR_NONE);
			return 0;
		}
	}

	coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);
	return -1;
}

int
coro_bus_try_send(struct coro_bus *bus, int channel, unsigned data)
{
	assert(bus != NULL);
	assert(channel >= 0);

	struct coro_bus_channel *chan = coro_bus_find_channel(bus, channel);
	if (chan == NULL || chan->about_to_close != 0) {
		coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);
		return -1;
	}

	if (coro_bus_is_channel_send_blocking(chan)) {
		coro_bus_errno_set(CORO_BUS_ERR_WOULD_BLOCK);
       	return -1;
	}

	coro_bus_send_internal(chan, data);
	coro_bus_errno_set(CORO_BUS_ERR_NONE);
	return 0;
}

static void
coro_bus_recv_internal(struct coro_bus_channel *chan, unsigned *data)
{
	assert(chan != NULL);
	assert(data != NULL);

	*data = data_vector_pop_first(&chan->data);
	wakeup_queue_wakeup_first(&chan->send_queue);
}

int
coro_bus_recv(struct coro_bus *bus, int channel, unsigned *data)
{
	assert(bus != NULL);
	assert(channel >= 0);
	assert(data != NULL);

	struct coro_bus_channel *chan = coro_bus_find_channel(bus, channel);
	if (chan == NULL) {
		coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);
		return -1;
	}

	while (chan->about_to_close == 0) {
		if (coro_bus_is_channel_recv_blocking(chan)) {
			wakeup_queue_suspend_this(&chan->recv_queue);
		}
		else {
			coro_bus_recv_internal(chan, data);
			coro_bus_errno_set(CORO_BUS_ERR_NONE);
			return 0;
		}
	}

	coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);
	return -1;
}

int
coro_bus_try_recv(struct coro_bus *bus, int channel, unsigned *data)
{
	assert(bus != NULL);
	assert(channel >= 0);
	assert(data != NULL);

	struct coro_bus_channel *chan = coro_bus_find_channel(bus, channel);
	if (chan == NULL || chan->about_to_close != 0) {
		coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);
		return -1;
	}

	if (coro_bus_is_channel_recv_blocking(chan)) {
		coro_bus_errno_set(CORO_BUS_ERR_WOULD_BLOCK);
		return -1;
	}

	coro_bus_recv_internal(chan, data);
	coro_bus_errno_set(CORO_BUS_ERR_NONE);
	return 0;
}

static int
coro_bus_realloc_channels(struct coro_bus *bus)
{
	assert(bus != NULL);

	for (; bus->channel_count > 0 && bus->channels[bus->channel_count - 1] == NULL; --bus->channel_count) { }

	size_t new_capacity = bus->channel_capacity;
	if (bus->channel_count * CAP_MULTIPLIER < bus->channel_capacity && bus->channel_capacity > INIT_CAPACITY) {
		new_capacity = bus->channel_capacity / CAP_MULTIPLIER;
	}
	else if (bus->channel_count == bus->channel_capacity) {
		new_capacity = bus->channel_capacity * CAP_MULTIPLIER;
	}

	if (new_capacity != bus->channel_capacity) {
		struct coro_bus_channel **new_channels = realloc(
			bus->channels,
			sizeof(struct coro_bus_channel *) * new_capacity
		);
		if (new_channels == NULL) {
			return -1;
		}

		bus->channels = new_channels;
		bus->channel_capacity = new_capacity;
	}

	return 0;
}


#if NEED_BROADCAST

static struct coro_bus_channel *
coro_bus_get_send_blocking_channel(struct coro_bus *bus)
{
	assert(bus != NULL);

	for (size_t i = 0; i < bus->channel_count; ++i) {
		struct coro_bus_channel *chan = bus->channels[i];
		if (chan != NULL && coro_bus_is_channel_send_blocking(chan)) {
			return chan;
		}
	}

	return NULL;
}

static void
coro_bus_broadcast_internal(struct coro_bus *bus, unsigned data)
{
	assert(bus != NULL);

	for (size_t i = 0; i < bus->channel_count; ++i) {
		struct coro_bus_channel *chan = bus->channels[i];
		if (chan != NULL) {
			coro_bus_send_internal(chan, data);
		}
	}
}

int
coro_bus_broadcast(struct coro_bus *bus, unsigned data)
{
	assert(bus != NULL);

	if (bus->channel_count == 0) {
		coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);
		return -1;
	}

	struct coro_bus_channel *blocking_chan = coro_bus_get_send_blocking_channel(bus);
	while (blocking_chan != NULL) {
		wakeup_queue_suspend_this(&blocking_chan->send_queue);
		blocking_chan = coro_bus_get_send_blocking_channel(bus);
	}

	coro_bus_broadcast_internal(bus, data);
	coro_bus_errno_set(CORO_BUS_ERR_NONE);
	return 0;
}

int
coro_bus_try_broadcast(struct coro_bus *bus, unsigned data)
{
	assert(bus != NULL);

	if (bus->channel_count == 0) {
		coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);
		return -1;
	}

	if (coro_bus_get_send_blocking_channel(bus) != NULL) {
		coro_bus_errno_set(CORO_BUS_ERR_WOULD_BLOCK);
		return -1;
	}

	coro_bus_broadcast_internal(bus, data);
	coro_bus_errno_set(CORO_BUS_ERR_NONE);
	return 0;
}

#endif

#if NEED_BATCH

static int
coro_bus_send_vector(struct coro_bus_channel *chan, const unsigned *data, unsigned count)
{
	assert(chan != NULL);
	assert(data != NULL);
	assert(count > 0);

	size_t sent_count = chan->size_limit - chan->data.size;
	if (sent_count > count) {
		sent_count = count;
	}

	data_vector_append_many(&chan->data, data, sent_count);
	wakeup_queue_wakeup_first(&chan->recv_queue);
	return sent_count;
}

int
coro_bus_send_v(struct coro_bus *bus, int channel, const unsigned *data, unsigned count)
{
	assert(bus != NULL);
	assert(channel >= 0);
	assert(data != NULL);

	if (count == 0) {
		coro_bus_errno_set(CORO_BUS_ERR_NONE);
		return 0;
	}

	struct coro_bus_channel *chan = coro_bus_find_channel(bus, channel);
	if (chan == NULL) {
		coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);
		return -1;
	}

	while (chan->about_to_close == 0) {
		if (coro_bus_is_channel_send_blocking(chan)) {
			wakeup_queue_suspend_this(&chan->send_queue);
		}
		else {
			int sent_count = coro_bus_send_vector(chan, data, count);
			coro_bus_errno_set(CORO_BUS_ERR_NONE);
			return sent_count;
		}
	}

	coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);
	return -1;
}

int
coro_bus_try_send_v(struct coro_bus *bus, int channel, const unsigned *data, unsigned count)
{
	assert(bus != NULL);
	assert(channel >= 0);
	assert(data != NULL);

	if (count == 0) {
		coro_bus_errno_set(CORO_BUS_ERR_NONE);
		return 0;
	}

	struct coro_bus_channel *chan = coro_bus_find_channel(bus, channel);
	if (chan == NULL || chan->about_to_close != 0) {
		coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);
		return -1;
	}

	if (coro_bus_is_channel_send_blocking(chan)) {
		coro_bus_errno_set(CORO_BUS_ERR_WOULD_BLOCK);
		return -1;
	}

	int sent_count = coro_bus_send_vector(chan, data, count);
	coro_bus_errno_set(CORO_BUS_ERR_NONE);
	return sent_count;
}

static int
coro_bus_recv_v_internal(struct coro_bus_channel *chan, unsigned *data, unsigned capacity)
{
	assert(chan != NULL);
	assert(data != NULL);
	assert(capacity > 0);

	size_t recv_count = (chan->data.size > capacity) ? capacity : chan->data.size;
	data_vector_pop_first_many(&chan->data, data, recv_count);
	wakeup_queue_wakeup_first(&chan->send_queue);
	wakeup_queue_wakeup_first(&chan->recv_queue);
	return recv_count;
}

int
coro_bus_recv_v(struct coro_bus *bus, int channel, unsigned *data, unsigned capacity)
{
	assert(bus != NULL);
	assert(channel >= 0);
	assert(data != NULL);

	if (capacity == 0) {
		coro_bus_errno_set(CORO_BUS_ERR_NONE);
		return 0;
	}

	struct coro_bus_channel *chan = coro_bus_find_channel(bus, channel);
	if (chan == NULL) {
		coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);
		return -1;
	}

	while (chan->about_to_close == 0) {
		if (coro_bus_is_channel_recv_blocking(chan)) {
			wakeup_queue_suspend_this(&chan->recv_queue);
		}
		else {
			int recv_count = coro_bus_recv_v_internal(chan, data, capacity);
			coro_bus_errno_set(CORO_BUS_ERR_NONE);
			return recv_count;
		}
	}

	coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);
	return -1;
}

int
coro_bus_try_recv_v(struct coro_bus *bus, int channel, unsigned *data, unsigned capacity)
{
	assert(bus != NULL);
	assert(channel >= 0);
	assert(data != NULL);

	if (capacity == 0) {
		coro_bus_errno_set(CORO_BUS_ERR_NONE);
		return 0;
	}

	struct coro_bus_channel *chan = coro_bus_find_channel(bus, channel);
	if (chan == NULL || chan->about_to_close != 0) {
		coro_bus_errno_set(CORO_BUS_ERR_NO_CHANNEL);
		return -1;
	}

	if (coro_bus_is_channel_recv_blocking(chan)) {
		coro_bus_errno_set(CORO_BUS_ERR_WOULD_BLOCK);
		return -1;
	}

	int recv_count = coro_bus_recv_v_internal(chan, data, capacity);
	coro_bus_errno_set(CORO_BUS_ERR_NONE);
	return recv_count;
}

#endif
