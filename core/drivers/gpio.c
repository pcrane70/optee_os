// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019 Broadcom.
 */

#include <assert.h>
#include <gpio.h>
#include <stdlib.h>
#include <trace.h>

static SLIST_HEAD(, gpio_desc) gdlist = SLIST_HEAD_INITIALIZER(gdlist);
static SLIST_HEAD(, gpio_chip) gclist = SLIST_HEAD_INITIALIZER(gclist);

static struct gpio_chip *gpio_pin_to_chip(unsigned int pin)
{
	struct gpio_chip *gc = NULL;

	SLIST_FOREACH(gc, &gclist, link)
		if ((pin >= gc->gpio_base) &&
		    (pin < (gc->gpio_base + gc->ngpios)))
			return gc;

	return NULL;
}

static bool __maybe_unused gpio_is_range_overlap(unsigned int start,
						 unsigned int end)
{
	struct gpio_chip *gc;

	SLIST_FOREACH(gc, &gclist, link)
		if ((start < (gc->gpio_base + gc->ngpios)) &&
		    (end > gc->gpio_base))
			return true;
	return false;
}

void gpio_set_direction(struct gpio_desc *gd, enum gpio_dir direction)
{
	gd->gc->ops->set_direction(gd->gc, gd->pin, direction);
}

enum gpio_dir gpio_get_direction(struct gpio_desc *gd)
{
	return gd->gc->ops->get_direction(gd->gc, gd->pin);
}

void gpio_set_value(struct gpio_desc *gd, enum gpio_level val)
{
	gd->gc->ops->set_value(gd->gc, gd->pin, val);
}

enum gpio_level gpio_get_value(struct gpio_desc *gd)
{
	return gd->gc->ops->get_value(gd->gc, gd->pin);
}

enum gpio_interrupt gpio_get_interrupt(struct gpio_desc *gd)
{
	return gd->gc->ops->get_interrupt(gd->gc, gd->pin);
}

void gpio_set_interrupt(struct gpio_desc *gd, enum gpio_interrupt ena_dis)
{
	gd->gc->ops->set_interrupt(gd->gc, gd->pin, ena_dis);
}

struct gpio_desc *request_gpiod(unsigned int pin)
{
	struct gpio_desc *gd = NULL;
	struct gpio_chip *gc = NULL;

	SLIST_FOREACH(gd, &gdlist, link)
		if (pin == gd->pin)
			break;

	if (gd == NULL) {
		gc = gpio_pin_to_chip(pin);
		if (gc == NULL) {
			EMSG("gpio chip not registered for %d\n", pin);
			return NULL;
		}

		gd = malloc(sizeof(*gd));
		gd->pin = pin;
		gd->gc = gc;
		SLIST_INSERT_HEAD(&gdlist, gd, link);

	} else {
		EMSG("gpio in use\n");
		return NULL;
	}

	return gd;
}

void release_gpiod(struct gpio_desc *gd)
{
	SLIST_REMOVE(&gdlist, gd, gpio_desc, link);
	free(gd);
}

void gpio_add_chip(struct gpio_chip *gc)
{
	assert(gc->ops);

	assert(!gpio_is_range_overlap(gc->gpio_base,
	       gc->gpio_base + gc->ngpios));

	SLIST_INSERT_HEAD(&gclist, gc, link);
}
