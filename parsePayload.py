# -*- coding: utf-8 -*-
"""
-------------------------------------------------
  File Name：   parseJoin
  Description :
  Author :    崔术森
  Eamil  :    deer_cui@163.com
  date：     2022/8/24
-------------------------------------------------
  Change Activity:
          2022/8/24:
-------------------------------------------------
"""
__author__ = '崔术森'

from Cryptodome.Cipher import AES
from Cryptodome.Hash import CMAC
import json


def hexlist2str(youlist):
    # list2str(['0x23', '0x55'])-->2355
    str = ""
    for x in youlist:
        s = x.replace("0x", '')
        if len(s) != 2:
            s = "0" + s
        str += s
    return str


def reverseHexStr(str):
    # E53C05D07ED5B370-->70b3d57ed0053ce5
    l = [hex(f) for f in bytes.fromhex(str)]
    l.reverse()
    return hexlist2str(l)


def hexStr2Binbit(str):
    # '80'-->10000000
    return '{0:08b}'.format(int(str, 16))


def lorawan_aes128_cmac(key, msg):
    """
    calculating the MIC.
        key, msg: in bytearray.
        return: 4 bytes MIC.
    """
    # key = bytearray.fromhex(key_hex)
    cmac = CMAC.new(key, ciphermod=AES)
    # cmac = AES_CMAC(bytearray.fromhex(key_hex))
    cmac.update(msg)
    m = cmac.digest()
    # print(m[:4][::-1].hex())
    # print("验证mic", m[:4].hex())
    print(m.hex())
    return {
        "mic": m[:4][::-1],
        "cmac": m
    }


def numstr2bytearr(num_str):
    # '80'-->bytearray(b'\x08\x00')
    b = bytearray()
    for i in num_str:
        b.append((int(i, 16)))
    return b


def append2_4b(num_str):
    # 补0够4字节
    # 1234-->00001234
    s = ''
    if len(num_str) < 8:
        append_len = 8 - len(num_str)
        s += '0' * append_len + num_str
    else:
        s = num_str
    return s


def binStr2int(binstr):
    # 0101-->5
    if binstr != '':
        return int(binstr, base=2)


def hexstr2int(hexstr):
    # 8c9830--9214000
    if hexstr != '':
        return int(hexstr, 16)


class parseMacCommand:
    def __init__(self, MHDR):
        self.json_str = {}
        self.mylist = []
        self.confirmUp = False
        self.unConfirmDown = False
        self.confirmDown = False
        if MHDR == '80':
            self.confirmUp = True
        elif MHDR == '60':
            self.unConfirmDown = True
        elif str(MHDR).upper() == 'A0':
            self.confirmDown = True

    def parse(self, macStr):
        # 递归解析80/60包的mac 即回复下行的mac
        youlist = self.mylist
        if len(macStr) <= 0:
            # print("没长度,退出", youlist)
            json_str = {}
            for index, v in enumerate(youlist):
                keys = v.keys()
                json_str_k = ''
                json_str_v = {}
                for k in keys:
                    if k == 'title':
                        json_str_k = '{}. {}'.format(index + 1, v[k])
                        if len(keys) <= 1:
                            json_str[json_str_k] = ''
                    elif k == 'Status':
                        ks = 'Status : x{}'.format(v['Status']['self_value'])
                        del v[k]['self_value']
                        json_str_v[ks] = v[k]
                    elif k == 'Margin':
                        if 'self_value' in v:
                            ks = 'Margin : x{}'.format(v['Margin']['self_value'])
                            del v[k]['self_value']
                            json_str_v[ks] = v[k]
                        else:
                            json_str_v['Margin'] = v[k]
                    elif k == 'Battery':
                        json_str_v['Battery'] = v[k]
                    elif k == 'GwCnt':
                        json_str_v['GwCnt'] = v[k]
                    elif k == 'DataRateTxPower':
                        ks = 'DataRateTxPower : x{}'.format(v['DataRateTxPower']['self_value'])
                        del v[k]['self_value']
                        json_str_v[ks] = v[k]
                    elif k == 'ChMask':
                        json_str_v['ChMask'] = v[k]
                    elif k == 'Redundancy':
                        ks = 'Redundancy : x{}'.format(v['Redundancy']['self_value'])
                        del v[k]['self_value']
                        json_str_v[ks] = v[k]
                    elif k == 'MaxDCycle':
                        json_str_v['MaxDCycle'] = v[k]
                    elif k == 'DLSettings':
                        ks = 'DLSettings : x{}'.format(v['DLSettings']['self_value'])
                        del v[k]['self_value']
                        json_str_v[ks] = v[k]
                    elif k == 'Frequency':
                        json_str_v['Frequency'] = v[k]
                    elif k == 'ChIndex':
                        json_str_v['ChIndex'] = v[k]
                    elif k == 'Freq':
                        json_str_v['Freq'] = v[k]
                    elif k == 'DrRange':
                        ks = 'DrRange : x{}'.format(v['DrRange']['self_value'])
                        del v[k]['self_value']
                        json_str_v[ks] = v[k]
                    elif k == 'Settings':
                        ks = 'Settings : x{}'.format(v['Settings']['self_value'])
                        del v[k]['self_value']
                        json_str_v[ks] = v[k]
                    elif k == 'EIRP_DwellTime':
                        ks = 'EIRP_DwellTime : x{}'.format(v['EIRP_DwellTime']['self_value'])
                        del v[k]['self_value']
                        json_str_v[ks] = v[k]
                    elif k == 'ChMask':
                        ks = 'ChMask : x{}'.format(v['ChMask']['self_value'])
                        del v[k]['self_value']
                        json_str_v[ks] = v[k]
                    json_str[json_str_k] = json_str_v
            self.json_str = json_str
        if macStr[:2] == '02':
            # print('LinkCheckReq')
            if self.confirmUp:
                # 80
                LinkCheckReq = {'title': 'LinkCheckReq : 0x {} Uplink'.format(macStr[:2])}
                youlist.append(LinkCheckReq)
                self.parse(macStr[2:])
            elif self.unConfirmDown:
                # 60
                LinkCheckAns = {'title': 'LinkCheckAns : 0x {} Downlink'.format(macStr[:2]),
                                'Margin': macStr[:6][2:4],
                                'GwCnt': macStr[:6][4:],
                                }
                youlist.append(LinkCheckAns)
                self.parse(macStr[6:])
                pass

            elif self.confirmDown:
                # A0
                pass

        if macStr[:2] == '03':
            # print('LinkADRAns')
            if self.confirmUp:
                # 80
                LinkADRAns = {}
                LinkADRAns['title'] = 'LinkADRAns : 0x {} Uplink'.format(macStr[:2])
                Status_title = macStr[:4][2:]
                Status = {}
                Status_bin = hexStr2Binbit(Status_title)
                Status['self_value'] = Status_title
                Status['RFU'] = Status_bin[:5]
                Status['Power ACK'] = Status_bin[5:6]
                Status['Data Rate ACK'] = Status_bin[6:7]
                Status['Channel Mask ACK'] = Status_bin[7:]

                LinkADRAns['Status'] = Status
                youlist.append(LinkADRAns)
                self.parse(macStr[4:])

            elif self.unConfirmDown:
                # 60
                LinkADRReq = {}
                LinkADRReq['title'] = 'LinkADRReq : 0x {} Downlink'.format(macStr[:2])
                DataRateTxPower_title = macStr[:10][2:4]
                DataRateTxPower = {}
                DataRateTxPower_bin = hexStr2Binbit(DataRateTxPower_title)
                DataRateTxPower['self_value'] = DataRateTxPower_title
                DataRateTxPower['DataRate'] = binStr2int(DataRateTxPower_bin[:4])
                DataRateTxPower['TxPower'] = binStr2int(DataRateTxPower_bin[4:])

                Redundancy_title = macStr[:10][8:]
                Redundancy = {}
                Redundancy_bin = hexStr2Binbit(Redundancy_title)
                Redundancy['self_value'] = Redundancy_title
                Redundancy['RFU'] = Redundancy_bin[:1]
                Redundancy['ChMaskCntl'] = Redundancy_bin[1:4]
                Redundancy['NbRep'] = binStr2int(Redundancy_bin[4:])

                ChMask = {}
                ChMask_title = macStr[:10][4:8]
                ChMask_bin = hexStr2Binbit(ChMask_title)
                ChMask['self_value'] = ChMask_title
                for i in enumerate(ChMask_bin):
                    ChMask['CH {}:'.format(i[0])] = True if i[1] == '1' else False
                LinkADRReq['DataRateTxPower'] = DataRateTxPower
                LinkADRReq['ChMask'] = ChMask
                LinkADRReq['Redundancy'] = Redundancy
                youlist.append(LinkADRReq)
                self.parse(macStr[10:])
            elif self.confirmDown:
                # A0
                pass

        if macStr[:2] == '04':
            # print('DutyCycleAns')
            if self.confirmUp:
                # 80
                DutyCycleAns = {}
                DutyCycleAns['title'] = 'DutyCycleAns : 0x {} Uplink'.format(macStr[:2])
                youlist.append(DutyCycleAns)
                self.parse(macStr[2:])
            elif self.unConfirmDown:
                # 60
                DutyCycleReq = {}
                DutyCycleReq['title'] = 'DutyCycleReq : 0x {} Downlink'.format(macStr[:2])
                DutyCycleReq['MaxDCycle'] = macStr[:4][2:]
                youlist.append(DutyCycleReq)
                self.parse(macStr[4:])
            elif self.confirmDown:
                # A0
                pass

        if macStr[:2] == '05':
            # print('RxParamSetupAns')
            if self.confirmUp:
                # 80
                RxParamSetupAns = {}
                RxParamSetupAns['title'] = 'RxParamSetupAns : 0x {} Uplink'.format(macStr[:2])
                Status_title = macStr[:4][2:]
                Status = {}
                Status_bin = hexStr2Binbit(Status_title)

                Status['self_value'] = Status_title
                Status['RFU'] = Status_bin[:5]
                Status['RX1DRoffset ACK'] = Status_bin[5:6]
                Status['RX2DRoffset ACK'] = Status_bin[6:7]
                Status['Channel ACK'] = Status_bin[7:]

                RxParamSetupAns['Status'] = Status
                youlist.append(RxParamSetupAns)
                self.parse(macStr[4:])
            elif self.unConfirmDown:
                # 60
                RxParamSetupReq = {}
                RxParamSetupReq['title'] = 'RxParamSetupReq : 0x {} Downlink'.format(macStr[:2])
                DLSettings_title = macStr[:10][2:4]
                DLSettings = {}
                DLSettings_bin = hexStr2Binbit(DLSettings_title)

                DLSettings['self_value'] = DLSettings_title
                DLSettings['RFU'] = DLSettings_bin[:2]
                DLSettings['RX1DRoffset'] = binStr2int(DLSettings_bin[2:4])
                DLSettings['RX2DataRate'] = binStr2int(DLSettings_bin[4:])

                RxParamSetupReq['DLSettings'] = DLSettings
                RxParamSetupReq['Frequency'] = hexstr2int(reverseHexStr(macStr[:10][4:]))
                youlist.append(RxParamSetupReq)
                self.parse(macStr[10:])
            elif self.confirmDown:
                # A0
                pass

        if macStr[:2] == '06':
            # print('DeviceStatusAns')
            if self.confirmUp:
                # 80
                DeviceStatusAns = {}
                DeviceStatusAns['title'] = 'DeviceStatusAns : 0x {} Uplink'.format(macStr[:2])
                DeviceStatusAns['Battery'] = macStr[:6][2:4]
                Margin_title = macStr[:6][4:]
                Margin_bin = hexStr2Binbit(Margin_title)
                Margin = {}
                Margin['self_value'] = Margin_title
                Margin['RFU'] = Margin_bin[:2]
                Margin['Margin'] = Margin_bin[2:]
                DeviceStatusAns['Margin'] = Margin

                youlist.append(DeviceStatusAns)
                self.parse(macStr[6:])
                pass

            elif self.unConfirmDown:
                # 60
                DeviceStatusReq = {}
                DeviceStatusReq['title'] = 'DeviceStatusReq : 0x {} Downlink'.format(macStr[:2])
                youlist.append(DeviceStatusReq)
                self.parse(macStr[2:])
            elif self.confirmDown:
                # A0
                pass

        if macStr[:2] == '07':
            # print('NewChannelAns')
            if self.confirmUp:
                # 80
                NewChannelAns = {}
                NewChannelAns['title'] = 'NewChannelAns : 0x {} Uplink'.format(macStr[:2])
                Status_title = macStr[:4][2:]
                Status_bin = hexStr2Binbit(Status_title)

                Status = {}
                Status['self_value'] = Status_title
                Status['RFU'] = Status_bin[:6]
                Status['Data Rate Range OK'] = Status_bin[6:7]
                Status['Channel Frequency OK'] = Status_bin[7:]
                NewChannelAns['Status'] = Status
                youlist.append(NewChannelAns)
                self.parse(macStr[4:])
            elif self.unConfirmDown:
                # 60
                NewChannelRq = {}
                NewChannelRq['title'] = 'NewChannelRq : 0x {} Downlink'.format(macStr[:2])
                DrRange_title = macStr[:12][10:]
                print('DrRange_titleDrRange_titleDrRange_title', DrRange_title)
                DrRange_bin = hexStr2Binbit(DrRange_title)

                DrRange = {}
                DrRange['self_value'] = DrRange_title
                DrRange['MaxDR'] = binStr2int(DrRange_bin[:4])
                DrRange['MinDR'] = binStr2int(DrRange_bin[4:])

                NewChannelRq['ChIndex'] = macStr[:12][2:4]
                NewChannelRq['Freq'] = hexstr2int(reverseHexStr(macStr[:12][4:10]))
                NewChannelRq['DrRange'] = DrRange
                youlist.append(NewChannelRq)
                self.parse(macStr[12:])
            elif self.confirmDown:
                # A0
                pass
        if macStr[:2] == '08':
            # print('RxTimingSetupAns')
            if self.confirmUp:
                # 80
                RxTimingSetupAns = {}
                RxTimingSetupAns['title'] = ['RxTimingSetupAns : 0x {} Uplink'.format(macStr[:2])]
                youlist.append(RxTimingSetupAns)
                self.parse(macStr[2:])
                pass

            elif self.unConfirmDown:
                # 60
                RxTimingSetupRq = {}
                RxTimingSetupRq['title'] = 'RxTimingSetupRq : 0x {} Downlink'.format(macStr[:2])

                Settings_title = macStr[:4][:2]
                Settings_bin = hexStr2Binbit(Settings_title)
                Settings = {}
                Settings['self_value'] = Settings_title
                Settings['RFU'] = Settings_bin[:4]
                Settings['Delay'] = Settings_bin[4:]

                RxTimingSetupRq['Settings'] = Settings
                youlist.append(RxTimingSetupRq)
                self.parse(macStr[4:])
                pass

            elif self.confirmDown:
                # A0
                pass
        if macStr[:2] == '09':
            if self.confirmUp:
                # 80
                TxParamSetupAns = {}
                TxParamSetupAns['title'] = 'TxParamSetupAns : 0x {} Uplink'.format(macStr[:2])
                youlist.append(TxParamSetupAns)
                self.parse(macStr[2:])
            elif self.unConfirmDown:
                # 60
                TxParamSetupReq = {}
                TxParamSetupReq['title'] = 'TxParamSetupReq : 0x {} Downlink'.format(macStr[:2])
                EIRP_DwellTime = {}
                EIRP_DwellTime_title = macStr[:4][2:]
                EIRP_DwellTime_bin = hexStr2Binbit(EIRP_DwellTime_title)
                EIRP_DwellTime['self_value'] = EIRP_DwellTime_title
                EIRP_DwellTime['RFU'] = EIRP_DwellTime_bin[:2]
                EIRP_DwellTime['Downlink_DwellTime'] = EIRP_DwellTime_bin[2:3]
                EIRP_DwellTime['Uplink_DwellTime'] = EIRP_DwellTime_bin[3:4]
                # codevalue:Max EIRP(dBm)
                MaxEIRP_talbe = {
                    '0': 8,
                    '1': 10,
                    '2': 12,
                    '3': 13,
                    '4': 14,
                    '5': 16,
                    '6': 18,
                    '7': 20,
                    '8': 21,
                    '9': 24,
                    '10': 26,
                    '11': 27,
                    '12': 29,
                    '13': 30,
                    '14': 33,
                    '15': 36,
                }
                codeValue = str(binStr2int(EIRP_DwellTime_bin[4:]))
                EIRP_DwellTime['MaxEIRP'] = MaxEIRP_talbe[codeValue]
                TxParamSetupReq['EIRP_DwellTime'] = EIRP_DwellTime
                youlist.append(TxParamSetupReq)
                self.parse(macStr[4:])
            elif self.confirmDown:
                # A0
                pass

        if macStr[:2].upper() == '0A':
            if self.confirmUp:
                # 80
                DlChannelAns = {}
                DlChannelAns['title'] = 'DlChannelAns : 0x {} Uplink'.format(macStr[:2])
                Status_title = macStr[:4][2:]
                Status_bin = hexStr2Binbit(Status_title)

                Status = {}
                Status['self_value'] = Status_title
                Status['RFU'] = Status_bin[:6]
                Status['Data Rate Range OK'] = Status_bin[6:7]
                Status['Channel Frequency OK'] = Status_bin[7:]
                DlChannelAns['Status'] = Status
                youlist.append(DlChannelAns)
                self.parse(macStr[4:])
            elif self.unConfirmDown:
                # 60
                DlChannelReq = {}
                DlChannelReq['title'] = 'DlChannelReq : 0x {} Downlink'.format(macStr[:2])
                DrRange_title = macStr[:12][10:]
                print('DrRange_titleDrRange_titleDrRange_title', DrRange_title)
                DrRange_bin = hexStr2Binbit(DrRange_title)

                DrRange = {}
                DrRange['self_value'] = DrRange_title
                DrRange['MaxDR'] = binStr2int(DrRange_bin[:4])
                DrRange['MinDR'] = binStr2int(DrRange_bin[4:])

                DlChannelReq['ChIndex'] = macStr[:12][2:4]
                DlChannelReq['Freq'] = hexstr2int(reverseHexStr(macStr[:12][4:10]))
                DlChannelReq['DrRange'] = DrRange
                youlist.append(DlChannelReq)
                self.parse(macStr[12:])
                pass
            elif self.confirmDown:
                # A0
                pass
        if macStr[:2].upper() == '0D':
            if self.confirmUp:
                # 80
                DeviceTimeReq = {}
                DeviceTimeReq['title'] = 'DeviceTimeReq : 0x {} Uplink'.format(macStr[:2])
                youlist.append(DeviceTimeReq)
                self.parse(macStr[2:])
            elif self.unConfirmDown:
                # 60:
                DeviceTimeAns = {}
                DeviceTimeAns['title'] = 'DeviceTimeAns : 0x {} Downlink'.format(macStr[:2])

                DeviceTimeAns['GPS time'] = macStr[:12][2:10]
                DeviceTimeAns['Fractional second'] = macStr[:12][10:]
                youlist.append(DeviceTimeAns)
                self.parse(macStr[12:])
            elif self.confirmDown:
                # A0
                pass


def parseJoin(join_str, appkey=None, version="1.0.3"):
    # join_str = '000000000000000000E53C05D07ED5B370F8EC97C00D1F'
    # MHDR+Mpayload+MIC  1-18-4
    if len(join_str) != 23 * 2:
        print("长度不对!")
        return
    if join_str[:2] != "00":
        print("不是入网00包")
        return
    MHDR_len = 1
    Mpayload_len = 18
    MIC_len = 4

    MHDR = join_str[:MHDR_len * 2]
    Mpayload = join_str[2:(Mpayload_len + 1) * 2]
    MIC = reverseHexStr(join_str[:-(MIC_len * 2) - 1:-1][::-1])
    # print("join_str={}\nMHDR={}\nMpayload={}\nMIC={}".format(join_str, MHDR, Mpayload, MIC))
    # print(bin(int(MHDR, 16)))

    AppEUI_len = DevEUI_len = 8
    DevNonce_len = 2
    AppEUI = reverseHexStr(Mpayload[:16:])
    DevEUI = reverseHexStr(Mpayload[16:32])
    DevNonce = reverseHexStr(Mpayload[32:len(Mpayload)])

    # print("Mpayload={}\nAppEUI={}\nDevEUI={}\nDevNonce={}\n".format(Mpayload, AppEUI, DevEUI, DevNonce))
    # 计算mic
    cutMicMsg = join_str[:-MIC_len * 2]
    print(cutMicMsg)
    calculateMic = None
    if appkey is not None:
        calculateMic = lorawan_aes128_cmac(bytearray.fromhex(appkey), bytearray.fromhex(cutMicMsg))['mic']
        # print("计算得出mic是{}\n帧中的mic是{}\n他们{}\n".format(calculateMic.hex(), MIC,
        #                                              "相等,mic校验正确" if calculateMic.hex() == MIC else "不相等,mic校验错误"))
    json_str = {}
    MHDR = {}
    MHDR['MType'] = 'Join-Request' if version == '1.0.3' else 'Join-request'
    MHDR['RFU'] = '000'
    MHDR['Major'] = 'LoRaWAN R1'
    Mpayload = {}
    Mpayload['AppEUI'] = AppEUI
    Mpayload['DevEUI'] = DevEUI
    Mpayload['DevNonce'] = DevNonce

    json_str['PHYpayload'] = join_str
    json_str['version'] = version
    json_str['MHDR'] = MHDR
    json_str['Mpayload'] = Mpayload
    json_str['MIC'] = MIC
    if appkey is not None and calculateMic is not None:
        json_str['calculateMIC'] = calculateMic.hex()
        json_str['micCheck'] = False if calculateMic.hex() != MIC else True

    print(json.dumps(json_str, indent=2))


def parseJoinAccept(joinAccept_str, appkey=None):
    if len(joinAccept_str) not in [17 * 2, 33 * 2]:
        print("入网回复包长度不对,请确认!")
        return
    PHYpayload = joinAccept_str
    print(len(joinAccept_str))
    MHDR = joinAccept_str[:2]
    Mpayload = joinAccept_str[2:]
    print("joinAccept_str={}\nMHDR={}\nMpayload={}\n".format(joinAccept_str, MHDR, Mpayload))
    if appkey is not None:
        aes = AES.new(bytearray.fromhex(appkey), AES.MODE_ECB)
        accpet_msg = (aes.encrypt(bytearray.fromhex(Mpayload)).hex())
        print(accpet_msg)
        AppNonce = accpet_msg[:6]
        NetID = accpet_msg[6:12]
        DevAddr = accpet_msg[12:20]
        DLSettings = accpet_msg[20:22]

        AppNonce_show = reverseHexStr(accpet_msg[:6])
        NetID_show = reverseHexStr(accpet_msg[6:12])
        DevAddr_show = reverseHexStr(accpet_msg[12:20])
        DLSettings_show = reverseHexStr(accpet_msg[20:22])

        # print('{0:08b}'.format(int(DLSettings, 16)))
        DLSettings_bin = '{0:08b}'.format(int(DLSettings, 16))
        # print(DLSettings_bin, type(DLSettings_bin))
        # DLSettings_bin='12345678'
        DLSettings_RFU = DLSettings_bin[:1]
        DLSettings_RX1DROffset = DLSettings_bin[1:4]
        DLSettings_RX2DataRate = DLSettings_bin[4:]
        RxDelay = accpet_msg[22:24]
        RxDelay_show = accpet_msg[22:24]
        CFList = ''
        CFList_Type = ''
        MIC = accpet_msg[:-8 - 1:-1][::-1]
        MIC_show = reverseHexStr(MIC)
        cutMicMsg = accpet_msg[:-8]
        calculateMic = lorawan_aes128_cmac(bytearray.fromhex(appkey), bytearray.fromhex(MHDR + cutMicMsg))['mic'].hex()
        CFList_show = []
        if len(joinAccept_str) == 33 * 2:
            CFList = accpet_msg[24:-8]
            range_count = 0
            for i in range(0, len(CFList), 6):
                list_i = CFList[i:i + 6]
                range_count += 1
                if range_count > 5:
                    CFList_Type = list_i
                else:
                    CFList_show.append(int.from_bytes(bytes.fromhex(list_i), byteorder='little'))
                # print(int.from_bytes(bytes.fromhex(list_i), byteorder='little'))
        # print(
        #     "AppNonce={}\nNetID={}\nDevAddr={}\nDLSettings={}\nRxDelay={}\nCFList={}\nMIC={}\ncalculateMic={}\n".format(
        #         AppNonce_show,
        #         NetID_show,
        #         DevAddr_show,
        #         DLSettings_show,
        #         RxDelay,
        #         CFList, MIC_show, calculateMic))
        # print("DLSettings_RFU={}\nDLSettings_RX1DROffset={}\nDLSettings_RX2DataRate={}".format(DLSettings_RFU,
        #                                                                                        DLSettings_RX1DROffset,
        #                                                                                        DLSettings_RX2DataRate))
    else:
        print("没有appkey,无法解析细节!")
    json_str = {}
    MHDR = {}
    # MHDR['MHDR'] ='20'
    MHDR['MType'] = 'Join-Accept'
    MHDR['RFU'] = '000'
    MHDR['Major'] = 'LoRaWAN R1'

    Mpayload = {}
    Mpayload['AppNonce'] = AppNonce_show
    Mpayload['NetID'] = NetID_show
    Mpayload['DevAddr'] = DevAddr_show

    DLSettings_show = {}
    DLSettings_show['RFU'] = int(DLSettings_RFU, base=2)
    DLSettings_show['RX1DROffset'] = int(DLSettings_RX1DROffset, base=2)
    DLSettings_show['RX2DataRate'] = int(DLSettings_RX2DataRate, base=2)
    Mpayload['DLSettings:{}'.format(DLSettings)] = DLSettings_show
    Mpayload['RxDelay'] = RxDelay_show
    Mpayload['CFList'] = CFList_show
    Mpayload['CFList_Type'] = CFList_Type

    json_str['MHDR'] = MHDR
    json_str['Mpayload'] = Mpayload
    json_str['MIC'] = MIC_show
    json_str['calculateMic'] = calculateMic
    json_str['micCheck'] = False if calculateMic != MIC_show else True

    print(json.dumps(json_str, indent=3))


def parseUpOrDown(PHYPayload=None, appskey=None, nwkskey=None):
    if PHYPayload is None:
        print('请输出PHYPayload')
        return
    # PHYPayload = "802BA1330180020002E78CF5A315"
    MHDR = PHYPayload[:2]
    # 判断80上行还是60下行
    isConfirmUp = False
    isConfirmDown = False
    isUnConfirmDown = False
    isUnConfirmUp = False
    if MHDR == '80':
        isConfirmUp = True
    if MHDR.upper() == 'A0':
        isConfirmDown = True
    if MHDR == '60':
        isUnConfirmDown = True
    if MHDR == '40':
        isUnConfirmUp = True
    MACPayload = PHYPayload[2:-8:]
    MIC = PHYPayload[:-8 - 1:-1][::-1]
    print(PHYPayload + "↓↓↓")
    print("MHDR={}\nMACPayload={}\nMIC={}\n".format(MHDR, MACPayload, reverseHexStr(MIC)))

    # 计算FOptlen长度，判断FHDR长度
    calculation_FOpt = MACPayload[:10][8:]
    calculation_FOptlen_bit = hexStr2Binbit(calculation_FOpt)
    calculation_FOptLen = binStr2int(calculation_FOptlen_bit[4:])

    MHDR_child = hexStr2Binbit(MHDR)
    Mtype = MHDR_child[:3]
    RFU = MHDR_child[3:6]
    Major = MHDR_child[6:]
    print(MHDR_child + "↓↓↓")
    print("Mtype={}\nRFU={}\nMajor={}\n".format(Mtype, RFU, Major))

    if calculation_FOptLen != 0:
        FHDR = MACPayload[:23 - 7 - 2 + calculation_FOptLen * 2]
        FPort = MACPayload[23 - 7 - 2 + calculation_FOptLen * 2:23 - 7 + calculation_FOptLen * 2]
        FRMPayload = MACPayload[23 - 7 + calculation_FOptLen * 2:]
    else:
        FHDR = MACPayload[:23 - 7 - 2]
        FPort = MACPayload[23 - 7 - 2:23 - 7]
        FRMPayload = MACPayload[23 - 7:]
    print(MACPayload + "↓↓↓")
    print("FHDR={}\nFPort={}\nFRMPayload={}\n".format(FHDR, FPort, FRMPayload))

    FHDR_devaddr = FHDR[:8]
    FHDR_FCtrl = FHDR[8:10]
    FHDR_FCnt = FHDR[10:14]
    FHDR_FOpts = FHDR[14:]
    print(FHDR + '↓↓↓')
    print(
        "FHDR_devaddr={}\nFHDR_FCtrl={}\nFHDR_FCnt={}\nFHDR_FOpts={}\n".format(reverseHexStr(FHDR_devaddr), FHDR_FCtrl,
                                                                               reverseHexStr(FHDR_FCnt), FHDR_FOpts))
    print(FHDR_FCtrl + 'FHDR_FCtrl↓↓↓', hexStr2Binbit(FHDR_FCtrl))
    FHDR_FCtrl_child = hexStr2Binbit(FHDR_FCtrl)
    ADR = FHDR_FCtrl_child[:1]
    ADRACKReq = FHDR_FCtrl_child[1:2]
    ACK = FHDR_FCtrl_child[2:3]
    DL = FHDR_FCtrl_child[3:4]
    FOptsLen = FHDR_FCtrl_child[4:]
    print("ADR={}\nADRACKReq={}\nACK={}\nDL={}\nFOptsLen={}\n".format(ADR, ADRACKReq, ACK, DL, FOptsLen))
    AppData = ''
    macCommand = ''
    if appskey is not None:
        # 解密appdata或者mac命令
        Ai = bytearray(16)
        Ai[0] = 0x01
        # Dir 上行为0x00，下行为0x01
        if isConfirmUp or isUnConfirmUp:
            Ai[5] = 0x00
        elif isConfirmDown or isUnConfirmDown:
            Ai[5] = 0x01
        # 需要bytearr 0133a12b-->bytearray(b'\x013\xa1+')
        DEVADDR = bytearray.fromhex(reverseHexStr(FHDR_devaddr))
        Ai[6] = DEVADDR[3]
        Ai[7] = DEVADDR[2]
        Ai[8] = DEVADDR[1]
        Ai[9] = DEVADDR[0]
        FCnt_Ai = bytearray.fromhex(append2_4b(reverseHexStr(FHDR_FCnt)))
        # 需要 0002-->bytearray(b'\x00\x00\x00\x02')
        Ai[10] = FCnt_Ai[3]
        Ai[11] = FCnt_Ai[2]
        Ai[12] = FCnt_Ai[1]
        Ai[13] = FCnt_Ai[0]

        ctr = 1
        app_msg = bytearray.fromhex(FRMPayload)
        app_msg_size = len(app_msg)
        S = bytearray(app_msg_size)
        print("appmsg-->", app_msg, app_msg.hex(), app_msg_size)
        decodeMac = False
        if FPort != '' and int(FPort, 16) != 0:
            aes = AES.new(bytearray.fromhex(appskey), AES.MODE_ECB)
        else:
            decodeMac = True
            aes = AES.new(bytearray.fromhex(nwkskey), AES.MODE_ECB)
        print("Ai-->", Ai, type(Ai), len(Ai), Ai.hex())
        print("s-->", S, len(S))
        offset = 0
        while app_msg_size > 16:
            Ai[15] = ctr & 0xff
            ctr += 1
            Si = aes.encrypt(Ai)
            for i in range(16):
                S[offset + i] = app_msg[offset + i] ^ Si[i]
            app_msg_size -= 16
            offset += 16
        if app_msg_size > 0:
            Ai[15] = ctr & 0xff
            Si = aes.encrypt(Ai)
            for i in range(app_msg_size):
                S[offset + i] = app_msg[offset + i] ^ Si[i]
        print("解密数据是【{}】".format(S.hex()), S, S.hex())
        if decodeMac:
            macCommand = S.hex()
        else:
            AppData = S.hex()
    else:
        print("没有appskey,无法解析appData数据。")

    # checkMic 校验MIC
    checkMic = ''
    if nwkskey is not None:
        msg = bytearray.fromhex(MHDR + FHDR + FPort + FRMPayload)
        print("****checkMic****", msg, len(msg))
        B0 = bytearray(16)
        B0[0] = 0x49
        # Dir 上行为0x00，下行为0x01
        if isConfirmUp or isUnConfirmUp:
            B0[5] = 0x00
        elif isConfirmDown or isUnConfirmDown:
            B0[5] = 0x01
        # put both devaddr and fcnt in little endian.
        # 需要bytearr 0133a12b-->bytearray(b'\x013\xa1+')
        DEVADDR = bytearray.fromhex(reverseHexStr(FHDR_devaddr))
        # 需要 0002-->bytearray(b'\x00\x00\x00\x02')
        FCnt_B0 = bytearray.fromhex(append2_4b(reverseHexStr(FHDR_FCnt)))
        B0[6] = DEVADDR[3]
        B0[7] = DEVADDR[2]
        B0[8] = DEVADDR[1]
        B0[9] = DEVADDR[0]
        B0[10] = FCnt_B0[3]
        B0[11] = FCnt_B0[2]
        B0[12] = FCnt_B0[1]
        B0[13] = FCnt_B0[0]
        B0[15] = len(msg)
        checkMic = lorawan_aes128_cmac(bytearray.fromhex(nwkskey), B0 + msg)['mic'].hex()
        print('checkMic={}\n'.format(checkMic))
    else:
        print('没有nwkskey,未校验mic，frame中的mic是{}'.format(reverseHexStr(MIC)))

    # showJson
    json_str = {}
    MHDR_show = {}
    if isConfirmUp:
        # 80
        MHDR_show['MType'] = 'Confirmed Data Up'
    elif isConfirmDown:
        # A0
        MHDR_show['MType'] = 'Confirmed Data Down'
    elif isUnConfirmDown:
        # 60
        MHDR_show['MType'] = 'Unconfirmed Data Down'
    elif isUnConfirmUp:
        # 40
        MHDR_show['MType'] = 'Unconfirmed Data Up'
    MHDR_show['RFU'] = RFU
    MHDR_show['Major'] = 'LoRaWAN R1'

    MACPayload_show = {}
    FHDR_show = {}
    FHDR_show['DevAddr'] = reverseHexStr(FHDR_devaddr)

    FHDR_FCtrl_show = {}
    FHDR_FCtrl_show['ADR'] = True if ADR == '1' else False
    FHDR_FCtrl_show['ADRACKReq'] = ADRACKReq
    FHDR_FCtrl_show['ACK'] = True if ACK == '1' else False
    if isConfirmUp or isUnConfirmUp:
        FHDR_FCtrl_show['RFU'] = DL
    else:
        FHDR_FCtrl_show['Fpending'] = True if DL == '1' else False
    FHDR_FCtrl_show['FOptsLen'] = binStr2int(FOptsLen)
    FHDR_show['FCtrl:{}'.format(FHDR_FCtrl)] = FHDR_FCtrl_show

    FHDR_show['FCnt'] = hexstr2int(reverseHexStr(FHDR_FCnt))
    FHDR_show['FHDR_FOpts'] = FHDR_FOpts

    MACPayload_show['FHDR:{}'.format(FHDR)] = FHDR_show
    MACPayload_show['FPort'] = hexstr2int(FPort)
    MACPayload_show['FRMPayload'] = FRMPayload
    if AppData != '':
        MACPayload_show['AppData'] = AppData
    if macCommand != '':
        # 展示解析的mac
        p = parseMacCommand(MHDR)
        p.parse(macCommand)
        MACPayload_show['macCommand:{}'.format(macCommand)] = p.json_str
    if calculation_FOptLen != 0:
        # 展示解析的FOpts
        p = parseMacCommand(MHDR)
        p.parse(FHDR_FOpts)
        MACPayload_show['macCommand:{}'.format(FHDR_FOpts)] = p.json_str

    MIC_show = {}
    if checkMic != '':
        MIC_show['calculateMic'] = checkMic
        MIC_show['checkMicResult'] = True if checkMic == reverseHexStr(MIC) else False
    json_str['MHDR:{}'.format(MHDR)] = MHDR_show
    json_str['MACPayload:{}'.format(MACPayload)] = MACPayload_show
    json_str['MIC:{}'.format(reverseHexStr(MIC))] = MIC_show

    print(json.dumps(json_str, indent=3))


if __name__ == "__main__":
    appkey = "d6adc8dbee8e9f16086a98d588ae3d5a"
    # join_str = '000000000000000000A682EDB3E3F49450843982F23EA3'
    # parseJoin(join_str, appkey)
    # joinAccept_str = '208D63224CA870750CC47975A14D87F112'
    # parseJoinAccept(joinAccept_str, appkey)
    parseUpOrDown(
        PHYPayload='604EA67300820200090476356D46',
        nwkskey='44d5564cba6d2616b25d7ee911ecdb6d',
        appskey='1ccb9aa91c878fe17790ca1b61e29511')
