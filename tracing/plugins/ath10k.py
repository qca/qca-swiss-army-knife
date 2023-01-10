#
# Copyright (c) 2012-2014,2016,2019 Qualcomm Atheros, Inc.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
# trace-cmd plugin for ath10k, QCA Linux wireless driver


import struct
import binascii


# enum htt_t2h_msg_type
HTT_T2H_MSG_TYPE_VERSION_CONF = 0x0
HTT_T2H_MSG_TYPE_RX_IND = 0x1
HTT_T2H_MSG_TYPE_RX_FLUSH = 0x2
HTT_T2H_MSG_TYPE_PEER_MAP = 0x3
HTT_T2H_MSG_TYPE_PEER_UNMAP = 0x4
HTT_T2H_MSG_TYPE_RX_ADDBA = 0x5
HTT_T2H_MSG_TYPE_RX_DELBA = 0x6
HTT_T2H_MSG_TYPE_TX_COMPL_IND = 0x7
HTT_T2H_MSG_TYPE_PKTLOG = 0x8
HTT_T2H_MSG_TYPE_STATS_CONF = 0x9
HTT_T2H_MSG_TYPE_RX_FRAG_IND = 0xa
HTT_T2H_MSG_TYPE_SEC_IND = 0xb
HTT_T2H_MSG_TYPE_TX_INSPECT_IND = 0xd
HTT_T2H_MSG_TYPE_MGMT_TX_COMPL_IND = 0xe
HTT_T2H_MSG_TYPE_TX_CREDIT_UPDATE_IND = 0xf
HTT_T2H_MSG_TYPE_RX_PN_IND = 0x10
HTT_T2H_MSG_TYPE_RX_OFFLOAD_DELIVER_IND = 0x11
HTT_T2H_MSG_TYPE_TEST = 0x12

# enum htt_dbg_stats_status
HTT_DBG_STATS_STATUS_PRESENT = 0
HTT_DBG_STATS_STATUS_PARTIAL = 1
HTT_DBG_STATS_STATUS_ERROR = 2
HTT_DBG_STATS_STATUS_INVALID = 3
HTT_DBG_STATS_STATUS_SERIES_DONE = 7

# enum htt_dbg_stats_type
HTT_DBG_STATS_WAL_PDEV_TXRX = 0
HTT_DBG_STATS_RX_REORDER = 1
HTT_DBG_STATS_RX_RATE_INFO = 2
HTT_DBG_STATS_TX_PPDU_LOG = 3
HTT_DBG_STATS_TX_RATE_INFO = 4
HTT_DBG_STATS_TIDQ = 5
HTT_DBG_STATS_TXBF_INFO = 6
HTT_DBG_STATS_SND_INFO = 7
HTT_DBG_STATS_ERROR_INFO = 8
HTT_DBG_STATS_TX_SELFGEN_INFO = 9
HTT_DBG_STATS_TX_MU_INFO = 10
HTT_DBG_STATS_SIFS_RESP_INFO = 11
HTT_DBG_STATS_RESET_INFO = 12
HTT_DBG_STATS_MAC_WDOG_INFO = 13
HTT_DBG_STATS_TX_DESC_INFO = 14
HTT_DBG_STATS_TX_FETCH_MGR_INFO = 15
HTT_DBG_STATS_TX_PFSCHED_INFO = 16


def hexdump(buf, prefix=None):
    s = binascii.b2a_hex(buf)
    s_len = len(s)
    result = ""

    if prefix is None:
        prefix = ""

    for i in range(s_len / 2):
        if i % 16 == 0:
            result = result + ("%s%04x: " % (prefix, i))

        result = result + (s[2 * i] + s[2 * i + 1] + " ")

        if (i + 1) % 16 == 0:
            result = result + "\n"

    # FIXME: if len(s) % 16 == 0 there's an extra \n in the end

    return result

wmi_scan_event_names = [
    [0x1, "WMI_SCAN_EVENT_STARTED"],
    [0x2, "WMI_SCAN_EVENT_COMPLETED"],
    [0x4, "WMI_SCAN_EVENT_BSS_CHANNEL"],
    [0x8, "WMI_SCAN_EVENT_FOREIGN_CHANNEL"],
    [0x10, "WMI_SCAN_EVENT_DEQUEUED"],
    [0x20, "WMI_SCAN_EVENT_PREEMPTED"],
    [0x40, "WMI_SCAN_EVENT_START_FAILED"],
]


def wmi_event_scan(pevent, trace_seq, event, buf):
    hdr = struct.unpack("<IIIIII", buf[0:24])
    event = hdr[0]
    reason = hdr[1]
    channel_freq = hdr[2]
    requestor = hdr[3]
    scan_id = hdr[4]
    vdev_id = hdr[5]

    trace_seq.puts("\t\t\t\tWMI_SCAN_EVENTID event 0x%x reason %d channel_freq %d requestor %d scan_id %d vdev_id %d\n" %
                   (event, reason, channel_freq, requestor, scan_id, vdev_id))

    for (i, name) in wmi_scan_event_names:
        if event == i:
            trace_seq.puts("\t\t\t\t\t%s" % name)

wmi_event_handlers = [
    [0x9000, wmi_event_scan],
]


def wmi_cmd_start_scan_handler(pevent, trace_seq, event, buf):
    hdr = struct.unpack("<IIIIIIIIIIIIIII", buf[0:60])
    scan_id = hdr[0]

    trace_seq.puts("\t\t\t\tWMI_START_SCAN_CMDID scan_id %d\n" % (scan_id))

wmi_cmd_handlers = [
    [0x9000, wmi_cmd_start_scan_handler],
]


def ath10k_wmi_cmd_handler(pevent, trace_seq, event):
    buf_len = int(event['buf_len'])
    buf = event['buf'].data

    # parse wmi header
    hdr = struct.unpack("<HH", buf[0:4])
    buf = buf[4:]

    cmd_id = hdr[0]

    trace_seq.puts("id 0x%x len %d\n" % (cmd_id, buf_len))

    for (wmi_id, handler) in wmi_cmd_handlers:
        if wmi_id == cmd_id:
            handler(pevent, trace_seq, event, buf)
            break


def ath10k_wmi_event_handler(pevent, trace_seq, event):
    buf_len = int(event['buf_len'])
    buf = event['buf'].data

    hdr = struct.unpack("<HH", buf[0:4])
    cmd_id = hdr[0]

    trace_seq.puts("id 0x%x len %d\n" % (cmd_id, buf_len))

    for (wmi_id, handler) in wmi_event_handlers:
        if wmi_id == cmd_id:
            handler(pevent, trace_seq, event, buf[4:])
            break


def ath10k_log_dbg_dump_handler(pevent, trace_seq, event):
    msg = event['msg']
    prefix = event['prefix']
    buf = event['buf'].data

    trace_seq.puts("%s\n" % (msg))
    trace_seq.puts("%s\n" % hexdump(buf, prefix))


def parse_htt_stats_wal_pdev_txrx(pevent, trace_seq, buf, tlv_length):
    msg_base_len = 136

    l = msg_base_len
    hdr = struct.unpack("<IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII", buf[0:l])
    buf = buf[l:]

    comp_queued = hdr[0]
    comp_delivered = hdr[1]
    msdu_enqued = hdr[2]
    mpdu_enqued = hdr[3]
    wmm_drop = hdr[4]
    local_enqued = hdr[5]
    local_freed = hdr[6]
    hw_queued = hdr[7]
    hw_reaped = hdr[8]
    underrun = hdr[9]
    hw_paused = hdr[10]
    tx_abort = hdr[11]
    mpdus_requed = hdr[12]
    tx_ko = hdr[13]
    data_rc = hdr[14]
    self_triggers = hdr[15]
    sw_retry_failure = hdr[16]
    illgl_rate_phy_err = hdr[17]
    pdev_cont_xretry = hdr[18]
    pdev_tx_timeout = hdr[19]
    pdev_resets = hdr[20]
    stateless_tid_alloc_failure = hdr[21]
    phy_underrun = hdr[22]
    txop_ovf = hdr[23]
    seq_posted = hdr[24]
    seq_failed_queueing = hdr[25]
    seq_completed = hdr[26]
    seq_restarted = hdr[27]
    mu_seq_posted = hdr[28]
    mpdus_sw_flush = hdr[29]
    mpdus_hw_filter = hdr[30]
    mpdus_truncated = hdr[31]
    mpdus_ack_failed = hdr[32]
    mpdus_expired = hdr[33]

    trace_seq.puts("\t\t\t Tx Stats\nhtt_cookies_queued %d htt_cookies_dispatched %d MSDU_queued %d MPDU_queue %d MSDUs_dropped %d local_frames_queued %d local_frames_done %d queued_to_HW %d PPDU_reaped %d underruns %d Hw_paused %d PPDUs_cleaned %d MPDUs_requed %d excessive_retries %d data_hw_rate_code %d scheduler_self_triggers %d dropped_due_to_sw retries %d illegal_rate_phy_errors %d pdev_continuous_xretry %d pdev_tx_timeout %d pdev_resets %d stateless_tid_alloc_failure %d phy_underrun %d MPDU_txop_limit %d seq_posted %d seq_failed_queueing %d seq_completed %d seq_restarted %d mu_seq_posted %d mpdus_sw_flush %d mpdus_hw_filter %d mpdus_truncated %d mpdus_ack_failed %d mpdus_expired %d\n"
                   % (comp_queued, comp_delivered, msdu_enqued, mpdu_enqued, wmm_drop, local_enqued, local_freed, hw_queued, hw_reaped, underrun, hw_paused, tx_abort, mpdus_requed, tx_ko, data_rc, self_triggers, sw_retry_failure, illgl_rate_phy_err, pdev_cont_xretry, pdev_tx_timeout, pdev_resets, stateless_tid_alloc_failure, phy_underrun, txop_ovf, seq_posted, seq_failed_queueing, seq_completed, seq_restarted, mu_seq_posted, mpdus_sw_flush, mpdus_hw_filter, mpdus_truncated, mpdus_ack_failed, mpdus_expired))

    msg_base_len = 60

    l = msg_base_len
    hdr = struct.unpack("<IIIIIIIIIIIIIII", buf[0:l])
    buf = buf[l:]

    mid_ppdu_route_change = hdr[0]
    status_rcvd = hdr[1]
    r0_frags = hdr[2]
    r1_frags = hdr[3]
    r2_frags = hdr[4]
    r3_frags = hdr[5]
    htt_msdus = hdr[6]
    htt_mpdus = hdr[7]
    loc_msdus = hdr[8]
    loc_mpdus = hdr[9]
    oversize_amsdu = hdr[10]
    phy_errs = hdr[11]
    phy_err_drop = hdr[12]
    mpdu_errs = hdr[13]
    rx_ovfl_errs = hdr[14]

    trace_seq.puts("\t\t\t Rx Stats\nmid_ppdu_route_change %d status_rcvd %d r0_frags %d r1_frags %d r2_frags %d r3_frags %d htt_msdus %d htt_mpdus %d loc_msdus %d loc_mpdus %d oversize_amsdu %d phy_errs %d phy_err_drop %d mpdu_errs %d rx_ovfl_errs %d\n" %
                   (mid_ppdu_route_change, status_rcvd, r0_frags, r1_frags, r2_frags, r3_frags, htt_msdus, htt_mpdus, loc_msdus, loc_mpdus, oversize_amsdu, phy_errs, phy_err_drop, mpdu_errs, rx_ovfl_errs))

    msg_base_len = 12

    l = msg_base_len
    hdr = struct.unpack("<III", buf[0:l])
    buf = buf[l:]

    iram_free_size = hdr[0]
    dram_free_size = hdr[1]
    sram_free_size = hdr[2]

    trace_seq.puts("\t\t\t Mem stats iram_free_size %d dram_free_size %d sram_free_size %d\n" %
                   (iram_free_size, dram_free_size, sram_free_size))


def parse_htt_stats_rx_reorder(pevent, trace_seq, buf, tlv_length):
    msg_base_len = 56

    l = msg_base_len
    hdr = struct.unpack("<IIIIIIIIIIIIII", buf[0:l])
    buf = buf[l:]

    deliver_non_qos = hdr[0]
    deliver_in_order = hdr[1]
    deliver_flush_timeout = hdr[2]
    deliver_flush_oow = hdr[3]
    deliver_flush_delba = hdr[4]
    fcs_error = hdr[5]
    mgmt_ctrl = hdr[6]
    invalid_peer = hdr[7]
    dup_non_aggr = hdr[8]
    dup_past = hdr[9]
    dup_in_reorder = hdr[10]
    reorder_timeout = hdr[11]
    invalid_bar_ssn = hdr[12]
    ssn_reset = hdr[13]

    trace_seq.puts("\t\t\tRx Reorder Stats\ndeliver_non_qos %d deliver_in_order %d deliver_flush_timeout %d deliver_flush_oow %d deliver_flush_delba %d fcs_error %d mgmt_ctrl %d invalid_peer %d dup_non_aggr %d dup_past %d dup_in_reorder %d reorder_timeout %d invalid_bar_ssn %d ssn_reset %d\n" %
                   (deliver_non_qos, deliver_in_order, deliver_flush_timeout, deliver_flush_oow, deliver_flush_delba, fcs_error, mgmt_ctrl, invalid_peer, dup_non_aggr, dup_past, dup_in_reorder, reorder_timeout, invalid_bar_ssn, ssn_reset))


def parse_htt_stats_rx_rate_info(pevent, trace_seq, buf, tlv_length):
    msg_base_len = 4

    trace_seq.puts("\t\t\tRx Rate Info\n\t\t MCS_counts ")

    for i in range(10):
        l = msg_base_len
        hdr = struct.unpack("<I", buf[0:l])
        buf = buf[l:]

        mcs_count = hdr[0]

        trace_seq.puts("%d " % (mcs_count))

    trace_seq.puts("\n\t\t SGI_counts ")

    for i in range(10):
        l = msg_base_len
        hdr = struct.unpack("<I", buf[0:l])
        buf = buf[l:]

        sgi_count = hdr[0]

        trace_seq.puts("%d " % (sgi_count))

    trace_seq.puts("\n\t\t NSS_count ")

    for i in range(4):
        l = msg_base_len
        hdr = struct.unpack("<I", buf[0:l])
        buf = buf[l:]

        nss_count = hdr[0]

        trace_seq.puts("%d " % (nss_count))

    l = msg_base_len
    hdr = struct.unpack("<I", buf[0:l])
    buf = buf[l:]

    nsts_count = hdr[0]

    trace_seq.puts("\n\t\t NSTS_count %d \n\t\t STBC " % (nsts_count))

    for i in range(10):
        l = msg_base_len
        hdr = struct.unpack("<I", buf[0:l])
        buf = buf[l:]

        stbc = hdr[0]

        trace_seq.puts("%d " % (stbc))

    trace_seq.puts("\n\t\t BW_counts ")

    for i in range(4):
        l = msg_base_len
        hdr = struct.unpack("<I", buf[0:l])
        buf = buf[l:]

        bw_count = hdr[0]

        trace_seq.puts("%d " % (bw_count))

    trace_seq.puts("\n\t\t Preamble_count ")

    for i in range(6):
        l = msg_base_len
        hdr = struct.unpack("<I", buf[0:l])
        buf = buf[l:]

        pream_count = hdr[0]

        trace_seq.puts("%d " % (pream_count))

    msg_base_len = 36

    l = msg_base_len
    hdr = struct.unpack("<IIIIIIBBBBII", buf[0:l])
    buf = buf[l:]

    ldpc_count = hdr[0]
    txbf_count = hdr[1]
    rssi_chain0 = hdr[2]
    rssi_chain1 = hdr[3]
    rssi_chain2 = hdr[4]
    rssi_chain3 = hdr[5]
    mgmt_rssi = hdr[6]
    data_rssi = hdr[7]
    rssi_comb_ht = hdr[8]
    #reserved = hdr[9]
    nf_dbm = hdr[10]
    rssi_dbm = hdr[11]

    # FIXME: no idea what rssis is supposed to be
    rssis = 0

    trace_seq.puts("\n\t\t ldpc_count %d \n\t\t txbf_count %d \n\t\t rssi_chain0 0x%02x 0x%02x 0x%02x 0x%02x \n\t\t rssi_chain1 0x%02x 0x%02x 0x%02x 0x%02x \n\t\t rssi_chain2 0x%02x 0x%02x 0x%02x 0x%02x \n\t\t rssi_chain3 0x%02x 0x%02x 0x%02x 0x%02x \n\t\t mgmt_rssi %d \n\t\t data_rssi %d \n\t\t rssi_comb_ht %d \n\t\t nf_dbm %d \n\t\t rssi_dbm %d" % (ldpc_count, txbf_count, (rssi_chain0 >> 24) & 0xff, (rssi_chain0 >> 16) & 0xff, (rssi_chain0 >> 8) & 0xff, (rssi_chain0 >> 0) & 0xff, (rssi_chain1 >> 24) & 0xff, (rssi_chain1 >> 16) & 0xff, (rssi_chain1 >> 8) & 0xff, (rssi_chain1 >> 0) & 0xff, (rssi_chain2 >> 24) & 0xff, (rssi_chain2 >> 16) & 0xff, (rssi_chain2 >> 8) & 0xff, (rssi_chain2 >> 0) & 0xff, (rssi_chain3 >> 24) & 0xff, (rssi_chain3 >> 16) & 0xff, (rssi_chain3 >> 8) & 0xff, (rssi_chain3 >> 0) & 0xff, (rssis >> 16) & 0xff, (rssis >> 0) & 0xff, (rssis >> 8) & 0xff, mgmt_rssi, data_rssi, rssi_comb_ht, nf_dbm, rssi_dbm))


def parse_htt_stats_tx_ppdu_log(pevent, trace_seq, buf, tlv_length):
    msg_hdr_len = 8
    msg_base_len = 40

    # struct ol_fw_tx_dbg_ppdu_msg_hdr
    l = msg_hdr_len
    hdr = struct.unpack("<BBBBI", buf[0:l])
    buf = buf[l:]

    mpdu_bytes_array_len = hdr[0]
    msdu_bytes_array_len = hdr[1]
    mpdu_msdus_array_len = hdr[2]
    reserved = hdr[3]
    microsec_per_tick = hdr[4]

    # 16 bit, 16 bit, 8 bit
    record_size = msg_base_len \
        + 2 * mpdu_bytes_array_len \
        + 2 * msdu_bytes_array_len \
        + 1 * mpdu_msdus_array_len
    records = (tlv_length - msg_hdr_len) / record_size

    trace_seq.puts("\t\t\trecords %d mpdu_bytes_array_len %d msdu_bytes_array_len %d mpdu_msdus_array_len %d reserved %d microsec_per_tick %d\n" %
                   (records, mpdu_bytes_array_len, msdu_bytes_array_len, mpdu_msdus_array_len, reserved, microsec_per_tick))

    for i in range(records):
        # struct ol_fw_tx_dbg_ppdu_base
        l = msg_base_len
        hdr = struct.unpack("<HHIBBHIIIIIIBBBB", buf[0:l])
        buf = buf[l:]

        start_seq_num = hdr[0]
        start_pn_lsbs = hdr[1]
        num_bytes = hdr[2]
        num_msdus = hdr[3]
        num_mpdus = hdr[4]
        tid = hdr[5] & 0x1f
        peer_id = (hdr[5] & 0xffe) >> 5
        timestamp_enqueue = hdr[6]
        timestamp_completion = hdr[7]
        block_ack_bitmap_lsbs = hdr[8]
        block_ack_bitmap_msbs = hdr[9]
        enqueued_bitmap_lsbs = hdr[10]
        enqueued_bitmap_msbs = hdr[11]
        rate_code = hdr[12]
        rate_flags = hdr[13]
        tries = hdr[14]
        complete = hdr[15]

        trace_seq.puts("\t\t\t %d: start_seq_num %d start_pn_lsbs %d num_bytes %d num_msdus %d num_mpdus %d tid %d peer_id %d timestamp_enqueue %d timestamp_completion %d back %08x%08x enqueued %08x%08x rate_code 0x%x rate_flags 0x%x tries %d complete %d\n" %
                       (i, start_seq_num, start_pn_lsbs, num_bytes, num_msdus, num_mpdus, tid, peer_id, timestamp_enqueue, timestamp_completion, block_ack_bitmap_msbs, block_ack_bitmap_lsbs, enqueued_bitmap_msbs, enqueued_bitmap_lsbs, rate_code, rate_flags, tries, complete))


def parse_htt_stats_tx_rate_info(pevent, trace_seq, buf, tlv_length):
    msg_base_len = 4

    trace_seq.puts("\t\t\tTx Rate Info\n\t\t MCS_counts ")

    for i in range(10):
        l = msg_base_len
        hdr = struct.unpack("<I", buf[0:l])
        buf = buf[l:]

        mcs_count = hdr[0]

        trace_seq.puts("%d " % (mcs_count))

    trace_seq.puts("\n\t\t SGI_counts ")

    for i in range(10):
        l = msg_base_len
        hdr = struct.unpack("<I", buf[0:l])
        buf = buf[l:]

        sgi_count = hdr[0]

        trace_seq.puts("%d " % (sgi_count))

    trace_seq.puts("\n\t\t NSS_count ")

    for i in range(4):
        l = msg_base_len
        hdr = struct.unpack("<I", buf[0:l])
        buf = buf[l:]

        nss_count = hdr[0]

        trace_seq.puts("%d " % (nss_count))

    trace_seq.puts("\n\t\t STBC ")

    for i in range(10):
        l = msg_base_len
        hdr = struct.unpack("<I", buf[0:l])
        buf = buf[l:]

        stbc = hdr[0]

        trace_seq.puts("%d " % (stbc))

    trace_seq.puts("\n\t\t BW_counts ")

    for i in range(4):
        l = msg_base_len
        hdr = struct.unpack("<I", buf[0:l])
        buf = buf[l:]

        bw_count = hdr[0]

        trace_seq.puts("%d " % (bw_count))

    trace_seq.puts("\n\t\t Preamble_count ")

    for i in range(4):
        l = msg_base_len
        hdr = struct.unpack("<I", buf[0:l])
        buf = buf[l:]

        pream_count = hdr[0]

        trace_seq.puts("%d " % (pream_count))

    msg_base_len = 12

    l = msg_base_len
    hdr = struct.unpack("<III", buf[0:l])
    buf = buf[l:]

    ldpc_count = hdr[0]
    rts_count = hdr[1]
    ack_rssi = hdr[2]

    trace_seq.puts("\n\t\t ldpc_count : %d \n\t\t rts_count : %d \n\t\t ack_rssi : %d" %
                   (ldpc_count, rts_count, ack_rssi))

    trace_seq.puts("\n\t\t MU MCS counts (0..9): ")

    msg_base_len = 4

    for i in range(10):
        l = msg_base_len
        hdr=struct.unpack("<I", buf[0:l])
        buf = buf[l:]

        mu_mcs = hdr[0]
        trace_seq.puts("%d " % (mu_mcs))

    trace_seq.puts("\n\t\t Mu_NSS ")

    for i in range(2):
        l = msg_base_len
        hdr = struct.unpack("<I", buf[0:l])
        buf = buf[l:]

        mu_nss = hdr[0]

        trace_seq.puts("%d " % (mu_nss))


def parse_htt_stats_tidq(pevent, trace_seq, buf, tlv_length):
    msg_base_len = 4

    l = msg_base_len
    hdr = struct.unpack("<I", buf[0:l])
    buf = buf[l:]

    wlan_dbg_tid_txq_status = hdr[0]

    if wlan_dbg_tid_txq_status == 1:
        trace_seq.puts("n\t Could not read TIDQ stats from firmware")
    else:
        trace_seq.puts("\n\t Frames queued to h/w Queue\n\t\t")
        msg_base_len = 2
        for i in range(10):
            l = msg_base_len
            hdr = struct.unpack("<H", buf[0:l])
            buf = buf[l:]

            num_pkts_queued = hdr[0]

            trace_seq.puts(" Q%d : %d" % (i, num_pkts_queued))

        trace_seq.puts("\n\t\t\t S/W Queue stats")
        for i in range(20):
            l = msg_base_len
            hdr = struct.unpack("<H", buf[0:l])
            buf = buf[l:]

            tid_sw_qdepth = hdr[0]

            trace_seq.puts("\n\t\t TID%d : %d" % (i, tid_sw_qdepth))

        trace_seq.puts("\n\t\t\t H/W Queue stats")
        for i in range(20):
            l = msg_base_len
            hdr = struct.unpack("<H", buf[0:l])
            buf = buf[l:]

            tid_hw_qdepth = hdr[0]

            trace_seq.puts("\n\t\t TID%d : %d" % (i, tid_hw_qdepth))


def parse_htt_stats_txbf_data_info(pevent, trace_seq, buf, tlv_length):
    msg_base_len = 4

    trace_seq.puts("\t\t TxBF Data Info\n\t\t VHT_TX_TxBF counts ")
    for i in range(10):
        l = msg_base_len
        hdr = struct.unpack("<I", buf[0:l])
        buf = buf[l:]

        tx_txbf_vht = hdr[0]

        trace_seq.puts(" %d" % (tx_txbf_vht))

    trace_seq.puts("\n\t\t VHT_RX_TxBF counts ")
    for i in range(10):
        l = msg_base_len
        hdr = struct.unpack("<I", buf[0:l])
        buf = buf[l:]

        rx_txbf_vht = hdr[0]

        trace_seq.puts(" %d" % (rx_txbf_vht))

    trace_seq.puts("\n\t\t HT_TX_TxBF counts ")
    for i in range(8):
        l = msg_base_len
        hdr = struct.unpack("<I", buf[0:l])
        buf = buf[l:]

        tx_txbf_ht = hdr[0]

        trace_seq.puts(" %d" % (tx_txbf_ht))

    trace_seq.puts("\n\t\t OFDM_TX_TxBF counts ")
    for i in range(8):
        l = msg_base_len
        hdr = struct.unpack("<I", buf[0:l])
        buf = buf[l:]

        tx_txbf_ofdm = hdr[0]

        trace_seq.puts(" %d" % (tx_txbf_ofdm))

    trace_seq.puts("\n\t\t ibf_VHT_TX_TxBF counts ")
    for i in range(10):
        l = msg_base_len
        hdr = struct.unpack("<I", buf[0:l])
        buf = buf[l:]

        tx_txbf_ofdm = hdr[0]

        trace_seq.puts(" %d" % (tx_txbf_ofdm))

    trace_seq.puts("\n\t\t ibf_HT_TX_TxBF counts ")
    for i in range(8):
        l = msg_base_len
        hdr = struct.unpack("<I", buf[0:l])
        buf = buf[l:]

        tx_txbf_ofdm = hdr[0]

        trace_seq.puts(" %d" % (tx_txbf_ofdm))

    trace_seq.puts("\n\t\t ibf_OFDM_TX_TxBF counts ")
    for i in range(8):
        l = msg_base_len
        hdr = struct.unpack("<I", buf[0:l])
        buf = buf[l:]

        tx_txbf_ofdm = hdr[0]

        trace_seq.puts(" %d" % (tx_txbf_ofdm))


def parse_htt_stats_txbf_send_info(pevent, trace_seq, buf, tlv_length):
    msg_base_len = 4

    trace_seq.puts("\t\t\tTx_BF SEND Info\n\t\t CBF_20 : ")
    for i in range(4):
        l = msg_base_len
        hdr = struct.unpack("<I", buf[0:l])
        buf = buf[l:]

        cbf_20 = hdr[0]

        trace_seq.puts(" %d" % (cbf_20))

    trace_seq.puts("\n\t\t BCF_40 : ")
    for i in range(4):
        l = msg_base_len
        hdr = struct.unpack("<I", buf[0:l])
        buf = buf[l:]

        cbf_40 = hdr[0]

        trace_seq.puts(" %d" % (cbf_40))

    trace_seq.puts("\n\t\t CBF_80 : ")
    for i in range(4):
        l = msg_base_len
        hdr = struct.unpack("<I", buf[0:l])
        buf = buf[l:]

        cbf_80 = hdr[0]

        trace_seq.puts(" %d" % (cbf_80))

    trace_seq.puts("\n\t\t CBF_160 :  ")
    for i in range(4):
        l = msg_base_len
        hdr = struct.unpack("<I", buf[0:l])
        buf = buf[l:]

        cbf_160 = hdr[0]

        trace_seq.puts(" %d" % (cbf_160))

    for i in range(3):
        trace_seq.puts(
            "\n\t\t Sounding_User_%d 20Mhz 40Mhz 80Mhz 160Mhz : " % (i))
        for j in range(4):
            l = msg_base_len
            hdr = struct.unpack("<I", buf[0:l])
            buf = buf[l:]

            sounding = hdr[0]

            trace_seq.puts(" %d" % (sounding))


def parse_htt_stats_tx_selfgen(pevent, trace_seq, buf, tlv_length):
    msg_base_len = 68

    l = msg_base_len
    hdr = struct.unpack("<IIIIIIIIIIIIIIIII", buf[0:l])
    buf = buf[l:]

    su_ndpa = hdr[0]
    su_ndp = hdr[1]
    mu_ndpa = hdr[2]
    mu_ndp = hdr[3]
    mu_brpoll_1 = hdr[4]
    mu_brpoll_2 = hdr[5]
    su_bar = hdr[6]
    mu_bar_1 = hdr[7]
    mu_bar_2 = hdr[8]
    su_cts = hdr[9]
    mu_cts = hdr[10]
    su_ndpa_err = hdr[11]
    mu_ndpa_err = hdr[12]
    su_ndp_err = hdr[13]
    mu_ndp_err = hdr[14]
    mu_brp1_err = hdr[15]
    mu_brp2_err = hdr[16]

    trace_seq.puts("\t\t\t Tx_Selfgen_info\n\t\tsu_ndpa %d su_ndp %d mu_ndpa %d mu_ndp %d mu_brpoll_1 %d mu_brpoll_2 %d su_bar %d mu_bar_1 %d mu_bar_2 %d su_cts %d mu_cts %d su_ndpa_err %d mu_ndpa_err %d su_ndp_err %d mu_ndp_err %d mu_brp1_err %d mu_brp2_err %d" %
                   (su_ndpa, su_ndp, mu_ndpa, mu_ndp, mu_brpoll_1, mu_brpoll_2, su_bar, mu_bar_1, mu_bar_2, su_cts, mu_cts, su_ndpa_err, mu_ndpa_err, su_ndp_err, mu_ndp_err, mu_brp1_err, mu_brp2_err))


def parse_htt_stats_tx_mu(pevent, trace_seq, buf, tlv_length):
    msg_base_len = 8

    l = msg_base_len
    hdr = struct.unpack("<II", buf[0:l])
    buf = buf[l:]

    mu_sch_nusers_2 = hdr[0]
    mu_sch_nusers_3 = hdr[1]

    trace_seq.puts("\t\t\tTx_MU_info\nmu_sch_nusers_2 : %dmu_sch_nusers_3 : %d " %
                   (mu_sch_nusers_2, mu_sch_nusers_3))

    msg_base_len = 4

    for i in range(4):
        l = msg_base_len
        hdr = struct.unpack("<I", buf[0:l])
        buf = buf[l:]
        mu_mpdus_queued_usr = hdr[0]

        trace_seq.puts(
            "mu_mpdus_queued_usr[%d] : %d " % (i, mu_mpdus_queued_usr))

    for i in range(4):
        l = msg_base_len
        hdr = struct.unpack("<I", buf[0:l])
        buf = buf[l:]
        mu_mpdus_tried_usr = hdr[0]

        trace_seq.puts(
            "mu_mpdus_tried_usr[%d] : %d " % (i, mu_mpdus_tried_usr))

    for i in range(4):
        l = msg_base_len
        hdr = struct.unpack("<I", buf[0:l])
        buf = buf[l:]
        mu_mpdus_failed_usr = hdr[0]

        trace_seq.puts(
            "mu_mpdus_failed_usr[%d] : %d " % (i, mu_mpdus_failed_usr))

    for i in range(4):
        l = msg_base_len
        hdr = struct.unpack("<I", buf[0:l])
        buf = buf[l:]
        mu_mpdus_requeued_usr = hdr[0]

        trace_seq.puts(
            "mu_mpdus_requeued_usr[%d] : %d " % (i, mu_mpdus_requeued_usr))

    for i in range(4):
        l = msg_base_len
        hdr = struct.unpack("<I", buf[0:l])
        buf = buf[l:]
        mu_err_no_ba_usr = hdr[0]

        trace_seq.puts("mu_err_no_ba_usr[%d] : %d " % (i, mu_err_no_ba_usr))

    for i in range(4):
        l = msg_base_len
        hdr = struct.unpack("<I", buf[0:l])
        buf = buf[l:]
        mu_mpdu_underrun_usr = hdr[0]

        trace_seq.puts(
            "mu_mpdu_underrun_usr[%d] : %d " % (i, mu_mpdu_underrun_usr))

    for i in range(4):
        l = msg_base_len
        hdr = struct.unpack("<I", buf[0:l])
        buf = buf[l:]
        mu_ampdu_underrun_usr = hdr[0]

        trace_seq.puts(
            "mu_ampdu_underrun_usr[%d] : %d " % (i, mu_ampdu_underrun_usr))


def parse_htt_stats_sifs_resp(pevent, trace_seq, buf, tlv_length):
    msg_base_len = 32

    l = msg_base_len
    hdr = struct.unpack("<IIIIIIII", buf[0:l])
    buf = buf[l:]

    ps_poll_trigger = hdr[0]
    uapsd_trigger = hdr[1]
    qb_data_trigger_exp = hdr[2]
    qb_data_trigger_imp = hdr[3]
    qb_bar_trigger_exp = hdr[4]
    qb_bar_trigger_imp = hdr[5]
    sifs_resp_data = hdr[6]
    sifs_resp_err = hdr[7]

    trace_seq.puts("\t\t\t SIFS Resp Rx Stats\ntps_poll_trigger : %d uapsd_trigger : %d qb_data_trigger[exp] : %d qb_data_trigger[imp] : %d qb_bar_trigger[exp] : %d qb_bar_trigger[imp] : %d\n\t\t\t SIFS Resp Tx Stats\nsifs_resp_data : %d sifs_resp_err : %d" % (
        ps_poll_trigger, uapsd_trigger, qb_data_trigger_exp, qb_data_trigger_imp, qb_bar_trigger_exp, qb_bar_trigger_imp, sifs_resp_data, sifs_resp_err))


def parse_htt_stats_reset(pevent, trace_seq, buf, tlv_length):
    msg_base_len = 16

    l = msg_base_len
    hdr = struct.unpack("<HHHHHHHH", buf[0:l])
    buf = buf[l:]

    warm_reset = hdr[0]
    cold_reset = hdr[1]
    tx_flush = hdr[2]
    tx_glb_reset = hdr[3]
    tx_txq_reset = hdr[4]
    rx_timeout_reset = hdr[5]
    hw_status_mismatch = hdr[6]
    hw_status_multi_mismatch = hdr[7]

    trace_seq.puts("\t\t\t Reset Stats\nwarm_reset : %d cold_reset : %d tx_flush : %d tx_glb_reset : %d tx_txq_reset : %d rx_timeout_reset : %d hw_status_mismatch : %d hw_status_multi_mismatch : %d" %
                   (warm_reset, cold_reset, tx_flush, tx_glb_reset, tx_txq_reset, rx_timeout_reset, hw_status_mismatch, hw_status_multi_mismatch))


def parse_htt_stats_mac_wdog(pevent, trace_seq, buf, tlv_length):

    msg_base_len = 16

    l = msg_base_len
    hdr = struct.unpack("<HHHHHHHH", buf[0:l])
    buf = buf[l:]

    rxpcu = hdr[0]
    txpcu = hdr[1]
    ole = hdr[2]
    rxdma = hdr[3]
    hwsch = hdr[4]
    crypto = hdr[5]
    pdg = hdr[6]
    txdma = hdr[7]

    trace_seq.puts("\n\t\t\t MAC WDOG timeout\nrxpcu : %d txpcu : %d ole : %d rxdma : %d hwsch : %d crypto : %d pdg : %d txdma : %d" %
                   (rxpcu, txpcu, ole, rxdma, hwsch, crypto, pdg, txdma))


def parse_htt_stats_tx_desc(pevent, trace_seq, buf, tlv_length):
    msg_base_len = 4

    l = msg_base_len
    hdr = struct.unpack("<I", buf[0:l])
    buf = buf[l:]

    word1 = hdr[0]

    trace_seq.puts("\n\t\t\t FW desc monitor stats\nTotal_FW_Desc_count:%d Current_desc_available:%d" %
                   ((((word1) & 0xFFFF) >> 0), (((word1) & 0xFFFF0000) >> 16)))

    for i in range(9):
        msg_base_len = 24

        l = msg_base_len
        hdr = struct.unpack("<IIIIII", buf[0:l])
        buf = buf[l:]

        cfg_min_bin_idx = hdr[0]
        cfg_prio_cfg_max = hdr[1]
        curr_total_cfg_bin_hist_th = hdr[2]
        bin_max_pre_alloc_cnt = hdr[3]
        bin_hist_low = hdr[4]
        bin_hist_high = hdr[5]

        trace_seq.puts("\n\t\tBIN id: %d Min desc: %d Max desc: %d Priority: %d Hysteresis threshold: %d Desc consumed: %d Pre-alloc count: %d Max Desc consumed: %d Low threshold count: %d High threshold count: %d" % (((cfg_min_bin_idx >> 0) & 0xFF), ((cfg_min_bin_idx >> 16) & 0xFFFF), (
            (cfg_prio_cfg_max >> 0) & 0xFFFF), ((cfg_prio_cfg_max >> 16) & 0xFF), ((curr_total_cfg_bin_hist_th >> 0) & 0xFFFF), ((curr_total_cfg_bin_hist_th >> 16) & 0xFFFF), ((bin_max_pre_alloc_cnt >> 0) & 0xFFFF), ((bin_max_pre_alloc_cnt >> 16) & 0xFFFF), bin_hist_low, bin_hist_high))


def parse_htt_stats_tx_fetch_mgr(pevent, trace_seq, buf, tlv_length):
    msg_base_len = 4

    l = msg_base_len
    trace_seq.puts("\t\t\t Fetch Manager Stats\n")
    for i in range(4):
        hdr = struct.unpack("<I", buf[0:l])
        buf = buf[l:]

        fetch_desc_fetch_dur = hdr[0]

        trace_seq.puts("Outstanding_Fetch_Duration : %d Outstanding_Fetch_Desc : %d\n" %
                       ((((fetch_desc_fetch_dur) & 0xFFFF) >> 0), (((fetch_desc_fetch_dur) & 0xFFFF0000) >> 16)))

    hdr = struct.unpack("<I", buf[0:l])
    buf = buf[l:]

    fetch_mgr_total_outstanding_fetch_desc = hdr[0]
    trace_seq.puts("Total Outstanding Fetch desc : %d\n\t\t Fetch Hist 400 msec bin" %
                   (fetch_mgr_total_outstanding_fetch_desc))

    msg_base_len = 64
    l = msg_base_len

    hdr = struct.unpack("<IIIIIIIIIIIIIIII", buf[0:l])

    fetch_mgr_rtt_histogram_4ms_0 = hdr[0]
    fetch_mgr_rtt_histogram_4ms_1 = hdr[1]
    fetch_mgr_rtt_histogram_4ms_2 = hdr[2]
    fetch_mgr_rtt_histogram_4ms_3 = hdr[3]
    fetch_mgr_rtt_histogram_4ms_4 = hdr[4]
    fetch_mgr_rtt_histogram_4ms_5 = hdr[5]
    fetch_mgr_rtt_histogram_4ms_6 = hdr[6]
    fetch_mgr_rtt_histogram_4ms_7 = hdr[7]
    fetch_mgr_rtt_histogram_500us_0 = hdr[8]
    fetch_mgr_rtt_histogram_500us_1 = hdr[9]
    fetch_mgr_rtt_histogram_500us_2 = hdr[10]
    fetch_mgr_rtt_histogram_500us_3 = hdr[11]
    fetch_mgr_rtt_histogram_500us_4 = hdr[12]
    fetch_mgr_rtt_histogram_500us_5 = hdr[13]
    fetch_mgr_rtt_histogram_500us_6 = hdr[14]
    fetch_mgr_rtt_histogram_500us_7 = hdr[15]

    trace_seq.puts(
        "\n0 MSEC - 4 MSEC:%d 4 MSEC - 8 MSEC:%d 8 MSEC - 12 MSEC:%d 12 MSEC - 16 MSEC:%d 16 MSEC - 20 MSEC:%d 20 MSEC - 24 MSEC:%d 24 MSEC - 28 MSEC:%d 28 MSEC - 32 MSEC:%d\n\t\tFetch Hist 500 usec bin\n0 USEC - 500 USEC:%d 500 USEC - 1000 USEC:%d 1000 USEC - 1500 USEC:%d 1500 USEC - 2000 USEC:%d 2000 USEC - 2500 USEC:%d 2500 USEC - 3000 USEC:%d 3000 USEC - 3500 USEC:%d 3500 USEC - 4000 USEC:%d" % (fetch_mgr_rtt_histogram_4ms_0, fetch_mgr_rtt_histogram_4ms_1,
                                                                                                                                                                                                                                                                                                                                                                                                                   fetch_mgr_rtt_histogram_4ms_2, fetch_mgr_rtt_histogram_4ms_3, fetch_mgr_rtt_histogram_4ms_4, fetch_mgr_rtt_histogram_4ms_5, fetch_mgr_rtt_histogram_4ms_6, fetch_mgr_rtt_histogram_4ms_7, fetch_mgr_rtt_histogram_500us_0, fetch_mgr_rtt_histogram_500us_1, fetch_mgr_rtt_histogram_500us_2, fetch_mgr_rtt_histogram_500us_3, fetch_mgr_rtt_histogram_500us_4, fetch_mgr_rtt_histogram_500us_5, fetch_mgr_rtt_histogram_500us_6, fetch_mgr_rtt_histogram_500us_7))


def parse_htt_stats_tx_pf_sched(pevent, trace_seq, buf, tlv_length):
    msg_base_len = 48
    l = msg_base_len

    trace_seq.puts("\n\t\t\tPre-Fetch Manager Stats")

    for i in range(4):
        hdr = struct.unpack("<IIIIIIIIIIII", buf[0:l])
        buf = buf[l:]

        tx_queued = hdr[0]
        tx_reaped = hdr[1]
        tx_sched = hdr[2]
        abort_sched = hdr[3]
        sched_timeout = hdr[4]
        tx_sched_waitq = hdr[5]
        fetch_resp = hdr[6]
        fetch_resp_invld = hdr[7]
        fetch_resp_delayed = hdr[8]
        fetch_request = hdr[9]
        tx_requeued = hdr[10]
        sched_fail = hdr[11]

        trace_seq.puts("\n\t\t AC[%d]\ntx_queued:%d tx_reaped:%d tx_sched:%d abort_sched:%d sched_timeout:%d tx_sched_waitq:%d fetch_resp:%d fetch_resp_invld:%d fetch_resp_delayed:%d fetch_request:%d tx_requeued:%d sched_fail:%d" %
                       (i, tx_queued, tx_reaped, tx_sched, abort_sched, sched_timeout, tx_sched_waitq, fetch_resp, fetch_resp_invld, fetch_resp_delayed, fetch_request, tx_requeued, sched_fail))

def parse_one_htt_stats_conf_msg(pevent, trace_seq, buf, tlv, cookie):
    # enum htt_dbg_stats_type: HTT_DBG_STATS_*
    tlv_type = (tlv >> 0) & 0x1f

    # enum htt_dbg_stats_status: HTT_DBG_STATS_STATUS_*
    tlv_status = (tlv & 0xe0) >> 5

    tlv_length = (tlv & 0xffff0000) >> 16

    if tlv_length > len(buf):
        return False

    if tlv_status == HTT_DBG_STATS_STATUS_SERIES_DONE:
        return False

    if tlv_status != HTT_DBG_STATS_STATUS_PRESENT and \
        tlv_status != HTT_DBG_STATS_STATUS_PARTIAL:
        return True

    trace_seq.puts("\t\tcookie 0x%016x tlv_type %d tlv_status %d tlv_length %d\n"
                   % (cookie, tlv_type, tlv_status, tlv_length))

    if tlv_type == HTT_DBG_STATS_WAL_PDEV_TXRX:
        parse_htt_stats_wal_pdev_txrx(pevent, trace_seq, buf, tlv_length)
    elif tlv_type == HTT_DBG_STATS_RX_REORDER:
        parse_htt_stats_rx_reorder(pevent, trace_seq, buf, tlv_length)
    elif tlv_type == HTT_DBG_STATS_RX_RATE_INFO:
        parse_htt_stats_rx_rate_info(pevent, trace_seq, buf, tlv_length)
    elif tlv_type == HTT_DBG_STATS_TX_PPDU_LOG:
        parse_htt_stats_tx_ppdu_log(pevent, trace_seq, buf, tlv_length)
    elif tlv_type == HTT_DBG_STATS_TX_RATE_INFO:
        parse_htt_stats_tx_rate_info(pevent, trace_seq, buf, tlv_length)
    elif tlv_type == HTT_DBG_STATS_TIDQ:
        parse_htt_stats_tidq(pevent, trace_seq, buf, tlv_length)
    elif tlv_type == HTT_DBG_STATS_TXBF_INFO:
        parse_htt_stats_txbf_data_info(pevent, trace_seq, buf, tlv_length)
    elif tlv_type == HTT_DBG_STATS_SND_INFO:
        parse_htt_stats_txbf_send_info(pevent, trace_seq, buf, tlv_length)
    elif tlv_type == HTT_DBG_STATS_TX_SELFGEN_INFO:
        parse_htt_stats_tx_selfgen(pevent, trace_seq, buf, tlv_length)
    elif tlv_type == HTT_DBG_STATS_TX_MU_INFO:
        parse_htt_stats_tx_mu(pevent, trace_seq, buf, tlv_length)
    elif tlv_type == HTT_DBG_STATS_SIFS_RESP_INFO:
        parse_htt_stats_sifs_resp(pevent, trace_seq, buf, tlv_length)
    elif tlv_type == HTT_DBG_STATS_RESET_INFO:
        parse_htt_stats_reset(pevent, trace_seq, buf, tlv_length)
    elif tlv_type == HTT_DBG_STATS_MAC_WDOG_INFO:
        parse_htt_stats_mac_wdog(pevent, trace_seq, buf, tlv_length)
    elif tlv_type == HTT_DBG_STATS_TX_DESC_INFO:
        parse_htt_stats_tx_desc(pevent, trace_seq, buf, tlv_length)
    elif tlv_type == HTT_DBG_STATS_TX_FETCH_MGR_INFO:
        parse_htt_stats_tx_fetch_mgr(pevent, trace_seq, buf, tlv_length)
    elif tlv_type == HTT_DBG_STATS_TX_PFSCHED_INFO:
        parse_htt_stats_tx_pf_sched(pevent, trace_seq, buf, tlv_length)

    return True

def parse_htt_stats_conf_msg(pevent, trace_seq, buf):
    # parse HTT_T2H_STATS_CONF_TLV
    l = 12
    hdr = struct.unpack("<III", buf[0:l])
    buf = buf[l:]

    # 64 bit cookie
    cookie = hdr[0] | (hdr[1] << 32)

    tlv = hdr[2]

    if parse_one_htt_stats_conf_msg(pevent, trace_seq, buf, tlv, cookie) == False:
        return

    tlv_length = (tlv & 0xffff0000) >> 16

    while len(buf) > tlv_length+4:
        buf = buf[tlv_length:]
        l = 4
        hdr = struct.unpack("<I", buf[0:l])
        buf = buf[l:]

        tlv = hdr[0]

        tlv_length = (tlv & 0xffff0000) >> 16

        if tlv_length == 0:
            continue

        if parse_one_htt_stats_conf_msg(pevent, trace_seq, buf, tlv, cookie) == False:
            break

def ath10k_htt_stats_handler(pevent, trace_seq, event):
    buf_len = int(event['buf_len'])
    buf = event['buf'].data

    l = 4
    hdr = struct.unpack("<I", buf[0:l])
    buf = buf[l:]

    # enum htt_t2h_msg_type: HTT_T2H_MSG_TYPE_*
    htt_type = hdr[0]

    trace_seq.puts("len %d type %d\n" % (buf_len, htt_type))

    if htt_type == HTT_T2H_MSG_TYPE_STATS_CONF:
        parse_htt_stats_conf_msg(pevent, trace_seq, buf)


def register(pevent):
    pevent.register_event_handler("ath10k", "ath10k_wmi_cmd",
                                  lambda *args:
                                      ath10k_wmi_cmd_handler(pevent, *args))
    pevent.register_event_handler("ath10k", "ath10k_wmi_event",
                                  lambda *args:
                                      ath10k_wmi_event_handler(pevent, *args))
    pevent.register_event_handler("ath10k", "ath10k_log_dbg_dump",
                                  lambda *args:
                                      ath10k_log_dbg_dump_handler(pevent, *args))
    pevent.register_event_handler("ath10k", "ath10k_htt_stats",
                                  lambda *args:
                                      ath10k_htt_stats_handler(pevent, *args))
