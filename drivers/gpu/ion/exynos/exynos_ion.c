/*
 * drivers/gpu/exynos/exynos_ion.c
 *
 * Copyright (C) 2011 Google, Inc.
 * Copyright (C) 2011 Samsung Electronics Co., Ltd.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/err.h>
#include <linux/ion.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include "../ion_priv.h"

struct ion_device *exynos_ion_dev;
struct ion_mapper *exynos_user_mapper;
int num_heaps;
struct ion_heap **heaps;
extern struct ion_heap *ion_exynos_heap_create(struct ion_platform_heap *unused);
extern void ion_exynos_heap_destroy(struct ion_heap *heap);

static struct ion_heap *exynos_ion_heap_create(struct ion_platform_heap *heap_data)
{
        struct ion_heap *heap = NULL;
	printk("%s: %d\n",__func__,__LINE__);
        switch (heap_data->type) {
	case ION_HEAP_TYPE_EXYNOS:
		heap = ion_exynos_heap_create(heap_data);
		break;
        default:
                return ion_heap_create(heap_data);
        }

        if (IS_ERR_OR_NULL(heap)) {
                pr_err("%s: error creating heap %s type %d base %lu size %u\n",
                       __func__, heap_data->name, heap_data->type,
                       heap_data->base, heap_data->size);
                return ERR_PTR(-EINVAL);
        }

        heap->name = heap_data->name;
        heap->id = heap_data->id;

        return heap;
}

void exynos_ion_heap_destroy(struct ion_heap *heap)
{
        if (!heap)
                return;

        switch (heap->type) {
	case ION_HEAP_TYPE_EXYNOS:
		ion_exynos_heap_destroy(heap);
		break;
	//ToDo: Add custom heap destroy here.
        default:
                ion_heap_destroy(heap);
        }
}

static long exynos_ion_ioctl(struct ion_client *client, unsigned int cmd,
                                unsigned long arg)
{
        int ret = 0;
	//ToDo: Add custom ioctl here.
	
        return ret;
}

int exynos_ion_probe(struct platform_device *pdev)
{
	struct ion_platform_data *pdata = pdev->dev.platform_data;
	int err;
	int i;

	num_heaps = pdata->nr;

	heaps = kzalloc(sizeof(struct ion_heap *) * pdata->nr, GFP_KERNEL);

	exynos_ion_dev = ion_device_create(&exynos_ion_ioctl);
	if (IS_ERR_OR_NULL(exynos_ion_dev)) {
		kfree(heaps);
		return PTR_ERR(exynos_ion_dev);
	}

	/* create the heaps as specified in the board file */
	for (i = 0; i < num_heaps; i++) {
		struct ion_platform_heap *heap_data = &pdata->heaps[i];

		heaps[i] = exynos_ion_heap_create(heap_data);
		if (IS_ERR_OR_NULL(heaps[i])) {
			err = PTR_ERR(heaps[i]);
			goto err;
		}
		ion_device_add_heap(exynos_ion_dev, heaps[i]);
	}
	platform_set_drvdata(pdev, exynos_ion_dev);
	return 0;
err:
	for (i = 0; i < num_heaps; i++) {
		if (heaps[i])
			exynos_ion_heap_destroy(heaps[i]);
	}
	kfree(heaps);
	return err;
}

int exynos_ion_remove(struct platform_device *pdev)
{
	struct ion_device *idev = platform_get_drvdata(pdev);
	int i;

	ion_device_destroy(idev);
	for (i = 0; i < num_heaps; i++)
		exynos_ion_heap_destroy(heaps[i]);
	kfree(heaps);
	return 0;
}

static struct platform_driver ion_driver = {
	.probe = exynos_ion_probe,
	.remove = exynos_ion_remove,
	.driver = { .name = "ion-exynos" }
};
static int __init ion_init(void)
{
        return platform_driver_register(&ion_driver);
}

subsys_initcall(ion_init);
