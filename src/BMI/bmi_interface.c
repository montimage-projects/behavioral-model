/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Antonin Bas (antonin@barefootnetworks.com)
 *
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>

#include <pcap/pcap.h>
#include "bmi_interface.h"

typedef struct bmi_interface_s {
  pcap_t *pcap;
  int fd;
  pcap_dumper_t *pcap_input_dumper;
  pcap_dumper_t *pcap_output_dumper;
  raw_packet_t last_recv_packet;
} bmi_interface_t;

/* static get_version(int *x, int *y, int *z) { */
/*   const char *str = pcap_lib_version(); */
/*   sscanf(str, "%*s %*s %d.%d.%d", x, y, z); */
/* } */

int bmi_interface_create(bmi_interface_t **bmi, const char *device) {
  bmi_interface_t *bmi_ = malloc(sizeof(bmi_interface_t));

  if(!bmi_) return -1;

  bmi_->pcap_input_dumper = NULL;
  bmi_->pcap_output_dumper = NULL;

  char errbuf[PCAP_ERRBUF_SIZE];
  bmi_->pcap = pcap_create(device, errbuf);

  if(!bmi_->pcap) {
    free(bmi_);
    return -1;
  }

  if(pcap_set_promisc(bmi_->pcap, 1) != 0) {
    pcap_close(bmi_->pcap);
    free(bmi_);
    return -1;
  }

#ifdef WITH_PCAP_FIX
  if(pcap_set_timeout(bmi_->pcap, 1) != 0) {
    pcap_close(bmi_->pcap);
    free(bmi_);
    return -1;
  }

  if(pcap_set_immediate_mode(bmi_->pcap, 1) != 0) {
    pcap_close(bmi_->pcap);
    free(bmi_);
    return -1;
  }
#endif

  if (pcap_activate(bmi_->pcap) != 0) {
    pcap_close(bmi_->pcap);
    free(bmi_);
    return -1;
  }

  bmi_->fd = pcap_get_selectable_fd(bmi_->pcap);
  if(bmi_->fd < 0) {
    pcap_close(bmi_->pcap);
    free(bmi_);
    return -1;
  }

  *bmi = bmi_;
  return 0;
}

int bmi_interface_destroy(bmi_interface_t *bmi) {
  pcap_close(bmi->pcap);
  if(bmi->pcap_input_dumper) pcap_dump_close(bmi->pcap_input_dumper);
  if(bmi->pcap_output_dumper) pcap_dump_close(bmi->pcap_output_dumper);
  free(bmi);
  return 0;
}

int bmi_interface_add_dumper(bmi_interface_t *bmi, const char *filename, bmi_dumper_kind_t dumper_kind) {
  pcap_dumper_t* dumper = pcap_dump_open(bmi->pcap, filename);
  if (dumper == NULL)
    return -1;
  switch (dumper_kind)
  {
  case bmi_input_dumper:
    bmi->pcap_input_dumper = dumper;
    break;
  case bmi_output_dumper:
    bmi->pcap_output_dumper = dumper;
    break;
  default:
    return -1;
  }
  return 0;
}

#define ETHERNET_HEADER_SIZE 14  // Ethernet header size (without VLAN tag)
#define VLAN_TAG_SIZE 4          // VLAN tag size
#define TPID_VLAN 0x8100         // TPID indicating a VLAN-tagged frame

/* Structure of an Ethernet frame with a VLAN tag:

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Destination MAC Address (6 bytes)                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Source MAC Address (6 bytes)                                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    EtherType (2 bytes) (0x8100 for VLAN Tag)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    VLAN ID (12 bits) | PCP (3 bits) | DEI (1 bit) | Reserved (2 bits) |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Payload/Data (46 - 1500 bytes)                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Frame Check Sequence (FCS) (4 bytes)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

// Function to extract the PCP field from a VLAN-tagged Ethernet frame
int extract_pcp(const uint8_t *frame, size_t frame_length) {
    if (frame_length < ETHERNET_HEADER_SIZE + VLAN_TAG_SIZE) {
        //printf("Frame is too short to contain a VLAN tag.\n");
        return -1;  // Indicate error
    }

    // Check if the frame contains a VLAN tag by examining the EtherType/TPID field
    uint16_t ether_type;
    memcpy(&ether_type, frame + 12, sizeof(ether_type));  // EtherType is after 12 bytes
    ether_type = ntohs(ether_type);  // Convert from network byte order to host byte order

    if (ether_type == TPID_VLAN) {
        // Frame contains a VLAN tag
        uint16_t tci;  // Tag Control Information (TCI)
        memcpy(&tci, frame + ETHERNET_HEADER_SIZE, sizeof(tci));  // TCI starts after Ethernet header
        tci = ntohs(tci);  // Convert from network byte order to host byte order

        // Extract the PCP field (first 3 bits of TCI)
        int pcp = (tci >> 13) & 0x07;  // Right shift by 13 bits, mask the first 3 bits (PCP)

        return pcp;  // Return the extracted PCP value
    } else {
        //printf("No VLAN tag present in the frame.\n");
        return -1;  // Indicate error
    }
}

int bmi_interface_send(bmi_interface_t *bmi, const char *data, int len) {
  if(bmi->pcap_output_dumper) {
    struct pcap_pkthdr pkt_header;
    memset(&pkt_header, 0, sizeof(pkt_header));
    gettimeofday(&pkt_header.ts, NULL);
    pkt_header.caplen = len;
    pkt_header.len = len;
    pcap_dump((unsigned char *) bmi->pcap_output_dumper, &pkt_header,
	      (unsigned char *) data);
    pcap_dump_flush(bmi->pcap_output_dumper);
  }

  //update skb->priority based on PCP field of vlan
  int pcp = extract_pcp( data, len );
  if( pcp >= 0 )
    setsockopt(pcap_fileno(bmi->pcap), SOL_SOCKET, SO_PRIORITY, &pcp, sizeof(pcp));

  return pcap_sendpacket(bmi->pcap, (unsigned char *) data, len);
}

/* Does not make a copy! */
int bmi_interface_recv(bmi_interface_t *bmi, const raw_packet_t **data) {
  struct pcap_pkthdr *pkt_header;
  const unsigned char *pkt_data;

  if(pcap_next_ex(bmi->pcap, &pkt_header, &pkt_data) != 1) {
    return -1;
  }

  if(pkt_header->caplen != pkt_header->len) {
    return -1;
  }

  if(bmi->pcap_input_dumper) {
    pcap_dump((unsigned char *) bmi->pcap_input_dumper, pkt_header, pkt_data);
    pcap_dump_flush(bmi->pcap_input_dumper);
  }

  //*data = (const char *) pkt_data;

  //expose more data than only packet data
  //update stat
  bmi->last_recv_packet.time = pkt_header->ts;
  bmi->last_recv_packet.data = pkt_data;
  bmi->last_recv_packet.len  = pkt_header->len;

  *data = (const char*) &bmi->last_recv_packet;

  return pkt_header->len;
}

int bmi_interface_stat(bmi_interface_t *bmi, const bmi_interface_stat_t **stat){
  *stat = &bmi->stat;
  return 0;
}

int bmi_interface_recv_with_copy(bmi_interface_t *bmi, char *data, int max_len) {
  int rv;
  struct pcap_pkthdr *pkt_header;
  const unsigned char *pkt_data;

  if(pcap_next_ex(bmi->pcap, &pkt_header, &pkt_data) != 1) {
    return -1;
  }

  if(pkt_header->caplen != pkt_header->len) {
    return -1;
  }

  if(bmi->pcap_input_dumper) {
    pcap_dump((unsigned char *) bmi->pcap_input_dumper, pkt_header, pkt_data);
    pcap_dump_flush(bmi->pcap_input_dumper);
  }

  rv = (max_len < pkt_header->len) ? max_len : pkt_header->len;

  memcpy(data, pkt_data, rv);

  return rv;
}

int bmi_interface_get_fd(bmi_interface_t *bmi) {
  return bmi->fd;
}
