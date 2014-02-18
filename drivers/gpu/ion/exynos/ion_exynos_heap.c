/*
 * drivers/gpu/ion/ion_system_heap.c
 *
 * Copyright (C) 2011 Google, Inc.
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

#include <asm/page.h>
#include <linux/dma-mapping.h>
#include <linux/err.h>
#include <linux/highmem.h>
#include <linux/ion.h>
#include <linux/mm.h>
#include <linux/scatterlist.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/bitops.h>
#include <linux/pagemap.h>
#include <asm/pgtable.h>
#include "../ion_priv.h"
/* IMBUFS stands for "InterMediate BUFfer Storage" */
#define IMBUFS_SHIFT	4
#define IMBUFS_ENTRIES	(1 << IMBUFS_SHIFT)
#define IMBUFS_MASK	(IMBUFS_ENTRIES - 1)	/* masking lower bits */
#define MAX_LV0IMBUFS	IMBUFS_ENTRIES
#define MAX_LV1IMBUFS	(IMBUFS_ENTRIES + IMBUFS_ENTRIES * IMBUFS_ENTRIES)
#define MAX_IMBUFS	(MAX_LV1IMBUFS + (IMBUFS_ENTRIES << (IMBUFS_SHIFT * 2)))

#define LV1IDX(lv1base)		((lv1base) >> IMBUFS_SHIFT)
#define LV2IDX1(lv2base)	((lv2base) >> (IMBUFS_SHIFT * 2))
#define LV2IDX2(lv2base)	(((lv2base) >> (IMBUFS_SHIFT)) & IMBUFS_MASK)

static int orders[] = {PAGE_SHIFT + 8, PAGE_SHIFT + 4, PAGE_SHIFT, 0};

static inline phys_addr_t *get_imbufs_and_free(int idx,
		phys_addr_t *lv0imbufs, phys_addr_t **lv1pimbufs,
		phys_addr_t ***lv2ppimbufs)
{
	if (idx < MAX_LV0IMBUFS) {
		return lv0imbufs;
	} else if (idx < MAX_LV1IMBUFS) {
		phys_addr_t *imbufs;
		idx -= MAX_LV0IMBUFS;
		imbufs = lv1pimbufs[LV1IDX(idx)];
		if ((LV1IDX(idx) == (IMBUFS_ENTRIES - 1)) ||
			(lv1pimbufs[LV1IDX(idx) + 1] == NULL))
			kfree(lv1pimbufs);
		return imbufs;
	} else if (idx < MAX_IMBUFS) {
		int baseidx;
		phys_addr_t *imbufs;
		baseidx = idx - MAX_LV1IMBUFS;
		imbufs = lv2ppimbufs[LV2IDX1(baseidx)][LV2IDX2(baseidx)];
		if ((LV2IDX2(baseidx) == (IMBUFS_ENTRIES - 1)) ||
			(lv2ppimbufs[LV2IDX1(baseidx)][LV2IDX2(baseidx) + 1]
				== NULL)) {
			kfree(lv2ppimbufs[LV2IDX1(baseidx)]);
			if ((LV2IDX1(baseidx) == (IMBUFS_ENTRIES - 1)) ||
				(lv2ppimbufs[LV2IDX1(baseidx) + 1] == NULL))
				kfree(lv2ppimbufs);
		}
		return imbufs;

	}
	return NULL;
}

static int ion_exynos_heap_allocate(struct ion_heap *heap,
		struct ion_buffer *buffer,
				     unsigned long size, unsigned long align,
				     unsigned long flags)
{
	int *cur_order = orders;
	int alloc_chunks = 0;
	int ret = 0;
	phys_addr_t *im_phys_bufs = NULL;
	phys_addr_t **pim_phys_bufs = NULL;
	phys_addr_t ***ppim_phys_bufs = NULL;
	phys_addr_t *cur_bufs = NULL;
	int copied = 0;
	struct scatterlist *sgl;
	struct sg_table *sgtable;

	while (size && *cur_order) {
		struct page *page;

		if (size < (1 << *cur_order)) {
			cur_order++;
			continue;
		}

		page = alloc_pages(GFP_HIGHUSER | __GFP_COMP |
						__GFP_NOWARN | __GFP_NORETRY,
						*cur_order - PAGE_SHIFT);
		if (!page) {
			cur_order++;
			continue;
		}

		if (alloc_chunks & IMBUFS_MASK) {
			cur_bufs++;
		} else if (alloc_chunks < MAX_LV0IMBUFS) {
			if (!im_phys_bufs)
				im_phys_bufs = kzalloc(
					sizeof(*im_phys_bufs) * IMBUFS_ENTRIES,
					GFP_KERNEL);
			if (!im_phys_bufs)
				break;

			cur_bufs = im_phys_bufs;
		} else if (alloc_chunks < MAX_LV1IMBUFS) {
			int lv1idx = LV1IDX(alloc_chunks - MAX_LV0IMBUFS);

			if (!pim_phys_bufs) {
				pim_phys_bufs = kzalloc(
					sizeof(*pim_phys_bufs) * IMBUFS_ENTRIES,
					GFP_KERNEL);
				if (!pim_phys_bufs)
					break;
			}

			if (!pim_phys_bufs[lv1idx]) {
				pim_phys_bufs[lv1idx] = kzalloc(
					sizeof(*cur_bufs) * IMBUFS_ENTRIES,
					GFP_KERNEL);
				if (!pim_phys_bufs[lv1idx])
					break;
			}

			cur_bufs = pim_phys_bufs[lv1idx];
		} else if (alloc_chunks < MAX_IMBUFS) {
			phys_addr_t **pcur_bufs;
			int lv2base = alloc_chunks - MAX_LV1IMBUFS;

			if (!ppim_phys_bufs) {
				ppim_phys_bufs = kzalloc(
					sizeof(*ppim_phys_bufs) * IMBUFS_ENTRIES
					, GFP_KERNEL);
				if (!ppim_phys_bufs)
					break;
			}

			if (!ppim_phys_bufs[LV2IDX1(lv2base)]) {
				ppim_phys_bufs[LV2IDX1(lv2base)] = kzalloc(
					sizeof(*pcur_bufs) * IMBUFS_ENTRIES,
					GFP_KERNEL);
				if (!ppim_phys_bufs[LV2IDX1(lv2base)])
					break;
			}
			pcur_bufs = ppim_phys_bufs[LV2IDX1(lv2base)];

			if (!pcur_bufs[LV2IDX2(lv2base)]) {
				pcur_bufs[LV2IDX2(lv2base)] = kzalloc(
					sizeof(*cur_bufs) * IMBUFS_ENTRIES,
					GFP_KERNEL);
				if (!pcur_bufs[LV2IDX2(lv2base)])
					break;
			}
			cur_bufs = pcur_bufs[LV2IDX2(lv2base)];
		} else {
			break;
		}

		*cur_bufs = page_to_phys(page) | *cur_order;

		size = size - (1 << *cur_order);
		alloc_chunks++;
	}

	if (size) {
		ret = -ENOMEM;
		goto alloc_error;
	}

	sgtable = kmalloc(sizeof(*sgtable), GFP_KERNEL);
	if (!sgtable) {
		ret = -ENOMEM;
		goto alloc_error;
	}

	if (sg_alloc_table(sgtable, alloc_chunks, GFP_KERNEL)) {
		ret = -ENOMEM;
		kfree(sgtable);
		goto alloc_error;
	}

	sgl = sgtable->sgl;
	while (copied < alloc_chunks) {
		int i;
		cur_bufs = get_imbufs_and_free(copied, im_phys_bufs,
						pim_phys_bufs, ppim_phys_bufs);
		BUG_ON(!cur_bufs);
		for (i = 0; (i < IMBUFS_ENTRIES) && cur_bufs[i]; i++) {
			phys_addr_t phys;
			int order;

			phys = cur_bufs[i];
			order = phys & ~PAGE_MASK;
			sg_set_page(sgl, phys_to_page(phys), 1 << order, 0);
			sg_dma_len(sgl) = (1 << order);
			sgl = sg_next(sgl);
			copied++;
		}

		kfree(cur_bufs);
	}

	buffer->priv_virt = sgtable;
	buffer->flags = flags;

	return 0;
alloc_error:
	copied = 0;
	while (copied < alloc_chunks) {
		int i;
		cur_bufs = get_imbufs_and_free(copied, im_phys_bufs,
				pim_phys_bufs, ppim_phys_bufs);
		for (i = 0; (i < IMBUFS_ENTRIES) && cur_bufs[i]; i++) {
			phys_addr_t phys;
			int gfp_order;

			phys = cur_bufs[i];
			gfp_order = (phys & ~PAGE_MASK) - PAGE_SHIFT;
			phys = phys & PAGE_MASK;
			__free_pages(phys_to_page(phys), gfp_order);
		}

		kfree(cur_bufs);
		copied += IMBUFS_ENTRIES;
	}

	return ret;
}

static void ion_exynos_heap_free(struct ion_buffer *buffer)
{
	struct scatterlist *sg;
	int i;
	struct sg_table *sgtable = buffer->priv_virt;

	for_each_sg(sgtable->sgl, sg, sgtable->orig_nents, i)
		__free_pages(sg_page(sg), __ffs(sg_dma_len(sg)) - PAGE_SHIFT);

	sg_free_table(sgtable);
	kfree(sgtable);
}

static struct sg_table *ion_exynos_heap_map_dma(struct ion_heap *heap,
						struct ion_buffer *buffer)
{
	return buffer->priv_virt;
}

static void ion_exynos_heap_unmap_dma(struct ion_heap *heap,
			       struct ion_buffer *buffer)
{
}

static void *ion_exynos_heap_map_kernel(struct ion_heap *heap,
				 struct ion_buffer *buffer)
{
	struct page **pages, **tmp_pages;
	struct sg_table *sgt;
	struct scatterlist *sgl;
	int num_pages, i;
	void *vaddr;

	sgt = buffer->priv_virt;
	num_pages = PAGE_ALIGN(offset_in_page(sg_phys(sgt->sgl)) + buffer->size)
								>> PAGE_SHIFT;

	pages = vmalloc(sizeof(*pages) * num_pages);
	if (!pages)
		return NULL;

	tmp_pages = pages;
	for_each_sg(sgt->sgl, sgl, sgt->orig_nents, i) {
		struct page *page = sg_page(sgl);
		unsigned int n =
			PAGE_ALIGN(sgl->offset + sg_dma_len(sgl)) >> PAGE_SHIFT;

		for (; n > 0; n--)
			*(tmp_pages++) = page++;
	}

	vaddr = vmap(pages, num_pages, VM_USERMAP | VM_MAP, PAGE_KERNEL);

	vfree(pages);

	return vaddr + offset_in_page(sg_phys(sgt->sgl));
}

static void ion_exynos_heap_unmap_kernel(struct ion_heap *heap,
				  struct ion_buffer *buffer)
{
	struct sg_table *sgt = buffer->priv_virt;

	vunmap(buffer->vaddr - offset_in_page(sg_phys(sgt->sgl)));
}

static int ion_exynos_heap_map_user(struct ion_heap *heap,
			struct ion_buffer *buffer, struct vm_area_struct *vma)
{
	struct sg_table *sgt = buffer->priv_virt;
	struct scatterlist *sgl;
	unsigned long pgoff;
	int i;
	unsigned long start;
	int map_pages;

	if (buffer->kmap_cnt)
		return remap_vmalloc_range(vma, buffer->vaddr, vma->vm_pgoff);

	pgoff = vma->vm_pgoff;
	start = vma->vm_start;
	map_pages = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
	vma->vm_flags |= VM_RESERVED;

	for_each_sg(sgt->sgl, sgl, sgt->orig_nents, i) {
		unsigned long sg_pgnum = sg_dma_len(sgl) >> PAGE_SHIFT;

		if (sg_pgnum <= pgoff) {
			pgoff -= sg_pgnum;
		} else {
			struct page *page = sg_page(sgl) + pgoff;
			int i;

			sg_pgnum -= pgoff;

			for (i = 0; (map_pages > 0) && (i < sg_pgnum); i++) {
				int ret;
				ret = vm_insert_page(vma, start, page);
				if (ret)
					return ret;
				start += PAGE_SIZE;
				page++;
				map_pages--;
			}

			pgoff = 0;

			if (map_pages == 0)
				break;
		}
	}

	return 0;
}
static struct ion_heap_ops vmheap_ops = {
	.allocate = ion_exynos_heap_allocate,
	.free = ion_exynos_heap_free,
	.map_dma = ion_exynos_heap_map_dma,
	.unmap_dma = ion_exynos_heap_unmap_dma,
	.map_kernel = ion_exynos_heap_map_kernel,
	.unmap_kernel = ion_exynos_heap_unmap_kernel,
	.map_user = ion_exynos_heap_map_user,
};
struct ion_heap *ion_exynos_heap_create(struct ion_platform_heap *unused)
{
	struct ion_heap *heap;

	heap = kzalloc(sizeof(struct ion_heap), GFP_KERNEL);
	if (!heap)
		return ERR_PTR(-ENOMEM);
	heap->ops = &vmheap_ops;
	heap->type = ION_HEAP_TYPE_EXYNOS;
	return heap;
}

void ion_exynos_heap_destroy(struct ion_heap *heap)
{
	kfree(heap);
}
