/******************************************************************************

  Copyright (c) 2013-2015, Intel Corporation 
  All rights reserved.
  
  Redistribution and use in source and binary forms, with or without 
  modification, are permitted provided that the following conditions are met:
  
   1. Redistributions of source code must retain the above copyright notice, 
      this list of conditions and the following disclaimer.
  
   2. Redistributions in binary form must reproduce the above copyright 
      notice, this list of conditions and the following disclaimer in the 
      documentation and/or other materials provided with the distribution.
  
   3. Neither the name of the Intel Corporation nor the names of its 
      contributors may be used to endorse or promote products derived from 
      this software without specific prior written permission.
  
  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.

******************************************************************************/
/*$FreeBSD$*/

#include <sys/limits.h>

#include "ixl.h"

/*
 * For dma memory allocation debugging
 */
char * const i40e_memory_type_strings[] = {
	"i40e_mem_arq_buf",
	"i40e_mem_asq_buf",
	"i40e_mem_atq_buf",
	"i40e_mem_arq_ring",
	"i40e_mem_atq_ring",
	"i40e_mem_pd",
	"i40e_mem_bp",
	"i40e_mem_bp_jumbo",
	"i40e_mem_reserved"
};

/********************************************************************
 * Manage DMA'able memory.
 *******************************************************************/
static void
i40e_dmamap_cb(void *arg, bus_dma_segment_t * segs, int nseg, int error)
{
        if (error)
                return;
        *(bus_addr_t *) arg = segs->ds_addr;
        return;
}

i40e_status
i40e_allocate_virt_mem(struct i40e_hw *hw, struct i40e_virt_mem *mem, u32 size)
{
	mem->va = malloc(size, M_DEVBUF, M_NOWAIT | M_ZERO);
	return(mem->va == NULL);
}

i40e_status
i40e_free_virt_mem(struct i40e_hw *hw, struct i40e_virt_mem *mem)
{
	free(mem->va, M_DEVBUF);
	return(0);
}

i40e_status
i40e_allocate_dma_mem(struct i40e_hw *hw, struct i40e_dma_mem *mem,
	enum i40e_memory_type type, u64 size, u32 alignment)
{
	device_t	dev = ((struct i40e_osdep *)hw->back)->dev;
	int		err;

	err = bus_dma_tag_create(bus_get_dma_tag(dev),	/* parent */
			       alignment, 0,	/* alignment, bounds */
			       BUS_SPACE_MAXADDR,	/* lowaddr */
			       BUS_SPACE_MAXADDR,	/* highaddr */
			       NULL, NULL,	/* filter, filterarg */
			       size,	/* maxsize */
			       1,	/* nsegments */
			       size,	/* maxsegsize */
			       BUS_DMA_ALLOCNOW, /* flags */
			       NULL,	/* lockfunc */
			       NULL,	/* lockfuncarg */
			       &mem->tag);
	if (err != 0) {
		device_printf(dev,
		    "i40e_allocate_dma: bus_dma_tag_create failed, "
		    "error %u\n", err);
		goto fail_0;
	}
	err = bus_dmamem_alloc(mem->tag, (void **)&mem->va,
			     BUS_DMA_NOWAIT | BUS_DMA_ZERO, &mem->map);
	if (err != 0) {
		device_printf(dev,
		    "i40e_allocate_dma: bus_dmamem_alloc failed, "
		    "error %u\n", err);
		goto fail_1;
	}
	err = bus_dmamap_load(mem->tag, mem->map, mem->va,
			    size,
			    i40e_dmamap_cb,
			    &mem->pa,
			    BUS_DMA_NOWAIT);
	if (err != 0) {
		device_printf(dev,
		    "i40e_allocate_dma: bus_dmamap_load failed, "
		    "error %u\n", err);
		goto fail_2;
	}
	mem->nseg = 1;
	mem->size = size;
	mem->type = type;
	bus_dmamap_sync(mem->tag, mem->map,
	    BUS_DMASYNC_PREREAD|BUS_DMASYNC_PREWRITE);
	return (0);
fail_2:
	bus_dmamem_free(mem->tag, mem->va, mem->map);
fail_1:
	bus_dma_tag_destroy(mem->tag);
fail_0:
	mem->map = NULL;
	mem->tag = NULL;
	return (err);
}

i40e_status
i40e_free_dma_mem(struct i40e_hw *hw, struct i40e_dma_mem *mem)
{
	bus_dmamap_sync(mem->tag, mem->map,
	    BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);
	bus_dmamap_unload(mem->tag, mem->map);
	bus_dmamem_free(mem->tag, mem->va, mem->map);
	bus_dma_tag_destroy(mem->tag);
	return (0);
}

void
i40e_init_spinlock(struct i40e_spinlock *lock)
{
	mtx_init(&lock->mutex, "mutex",
	    "ixl spinlock", MTX_DEF | MTX_DUPOK);
}

void
i40e_acquire_spinlock(struct i40e_spinlock *lock)
{
	mtx_lock(&lock->mutex);
}

void
i40e_release_spinlock(struct i40e_spinlock *lock)
{
	mtx_unlock(&lock->mutex);
}

void
i40e_destroy_spinlock(struct i40e_spinlock *lock)
{
	if (mtx_initialized(&lock->mutex))
		mtx_destroy(&lock->mutex);
}

void
i40e_msec_pause(int msecs)
{
	int ticks_to_pause = (msecs * hz) / 1000;
	int start_ticks = ticks;

	if (cold || SCHEDULER_STOPPED()) {
		i40e_msec_delay(msecs);
		return;
	}

	while (1) {
		kern_yield(PRI_USER);
		int yielded_ticks = ticks - start_ticks;
		if (yielded_ticks > ticks_to_pause)
			break;
		else if (yielded_ticks < 0
		    && (yielded_ticks + INT_MAX + 1 > ticks_to_pause)) {
			break;
		}
	}
}

/*
 * Helper function for debug statement printing
 */
void
i40e_debug_shared(struct i40e_hw *hw, enum i40e_debug_mask mask, char *fmt, ...)
{
	va_list args;
	device_t dev;

	if (!(mask & ((struct i40e_hw *)hw)->debug_mask))
		return;

	dev = ((struct i40e_osdep *)hw->back)->dev;

	/* Re-implement device_printf() */
	device_print_prettyname(dev);
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
}

const char *
ixl_vc_opcode_str(uint16_t op)
{
	switch (op) {
	case I40E_VIRTCHNL_OP_VERSION:
		return ("VERSION");
	case I40E_VIRTCHNL_OP_RESET_VF:
		return ("RESET_VF");
	case I40E_VIRTCHNL_OP_GET_VF_RESOURCES:
		return ("GET_VF_RESOURCES");
	case I40E_VIRTCHNL_OP_CONFIG_TX_QUEUE:
		return ("CONFIG_TX_QUEUE");
	case I40E_VIRTCHNL_OP_CONFIG_RX_QUEUE:
		return ("CONFIG_RX_QUEUE");
	case I40E_VIRTCHNL_OP_CONFIG_VSI_QUEUES:
		return ("CONFIG_VSI_QUEUES");
	case I40E_VIRTCHNL_OP_CONFIG_IRQ_MAP:
		return ("CONFIG_IRQ_MAP");
	case I40E_VIRTCHNL_OP_ENABLE_QUEUES:
		return ("ENABLE_QUEUES");
	case I40E_VIRTCHNL_OP_DISABLE_QUEUES:
		return ("DISABLE_QUEUES");
	case I40E_VIRTCHNL_OP_ADD_ETHER_ADDRESS:
		return ("ADD_ETHER_ADDRESS");
	case I40E_VIRTCHNL_OP_DEL_ETHER_ADDRESS:
		return ("DEL_ETHER_ADDRESS");
	case I40E_VIRTCHNL_OP_ADD_VLAN:
		return ("ADD_VLAN");
	case I40E_VIRTCHNL_OP_DEL_VLAN:
		return ("DEL_VLAN");
	case I40E_VIRTCHNL_OP_CONFIG_PROMISCUOUS_MODE:
		return ("CONFIG_PROMISCUOUS_MODE");
	case I40E_VIRTCHNL_OP_GET_STATS:
		return ("GET_STATS");
	case I40E_VIRTCHNL_OP_FCOE:
		return ("FCOE");
	case I40E_VIRTCHNL_OP_EVENT:
		return ("EVENT");
	case I40E_VIRTCHNL_OP_CONFIG_RSS_KEY:
		return ("CONFIG_RSS_KEY");
	case I40E_VIRTCHNL_OP_CONFIG_RSS_LUT:
		return ("CONFIG_RSS_LUT");
	case I40E_VIRTCHNL_OP_GET_RSS_HENA_CAPS:
		return ("GET_RSS_HENA_CAPS");
	case I40E_VIRTCHNL_OP_SET_RSS_HENA:
		return ("SET_RSS_HENA");
	default:
		return ("UNKNOWN");
	}
}

u16
i40e_read_pci_cfg(struct i40e_hw *hw, u32 reg)
{
        u16 value;

        value = pci_read_config(((struct i40e_osdep *)hw->back)->dev,
            reg, 2);

        return (value);
}

void
i40e_write_pci_cfg(struct i40e_hw *hw, u32 reg, u16 value)
{
        pci_write_config(((struct i40e_osdep *)hw->back)->dev,
            reg, value, 2);

        return;
}

