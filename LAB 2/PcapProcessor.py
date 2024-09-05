#! /bin/python
# -*- coding: utf-8 -*-
#
#  PcapProcessor.py
#
#  Explication: The PcapProcessor class is designed to automate the process of extracting
# features from pcap files for IoT device detection. It encapsulates the entire workflow, 
# including initializing a CSV file, filtering pcap files based on device-specific 
# IP addresses, and extracting relevant network traffic features using tshark. The class 
# methods are organized to handle each step, and the process method runs the full extraction
# pipeline. This object-oriented structure allows for easy reuse, extension, and clarity in 
# managing pcap file processing tasks.

import os 
import glob

__author__ = "Mohamed Djallel DILMI"
__copyright__ = "Copyright 2024, The IOT Detection Lab for RS"
__credits__ = ["Mohamed Djallel DILMI"]
__license__ = "Open Core"
__version__ = "0.0.1"
__maintainer__ = "Djallel DILMI"
__email__ = "djallel.dilmi@outlook.fr"
__status__ = "Academic code"


class PcapProcessor:
    """
    
    >> # Example Usage:
    >> processor = PcapProcessor(pcap_folder='original_pcap')
    >> processor.process()
    >> print(processor.get_csv())
    
    """
    def __init__(self, pcap_folder="/content/filtered_pcap", output_csv="label_feature_IOT.csv", ip_filter=None):
        """
        Initializes the PcapProcessor with a folder of pcap files and the output CSV file.

        :param pcap_folder: The folder containing the pcap files to process.
        :param output_csv: The name of the CSV file where features will be saved.
        """
        self.pcap_folder = pcap_folder
        self.output_csv = output_csv
        if ip_filter is None :
            self.ip_filter = {
                'TCP_Mobile': "tcp && (ip.src==192.168.1.45)",
                'TCP_Outlet': "tcp && (ip.src==192.168.1.222) || (ip.src==192.168.1.67)",
                'TCP_Assistant': "tcp && (ip.src==192.168.1.111) || (ip.src==192.168.1.30) || "
                                 "(ip.src==192.168.1.42) || (ip.src==192.168.1.59) || "
                                 "(ip.src==192.168.1.70)",
                'TCP_Camera': "tcp && (ip.src==192.168.1.128) || (ip.src==192.168.1.145) || "
                              "(ip.src==192.168.1.78)",
                'TCP_Miscellaneous': "tcp && (ip.src==192.168.1.216) || (ip.src==192.168.1.46) || "
                                     "(ip.src==192.168.1.84) || (ip.src==192.168.1.91)"
            }
        else:
            self.ip_filter = ip_filter


    def initialize_csv(self):
        """
        Initializes the CSV file with the appropriate header.
        """
        header = (
            "Label,IPLength,IPHeaderLength,TTL,Protocol,SourcePort,DestPort,"
            "SequenceNumber,AckNumber,WindowSize,TCPHeaderLength,TCPLength,"
            "TCPStream,TCPUrgentPointer,IPFlags,IPID,IPchecksum,TCPflags,TCPChecksum\n"
        )
        with open(self.output_csv, 'w') as label_feature:
            label_feature.write(header)

    def extract_features(self):
        """
        Extracts features from the filtered pcap files and writes them to the CSV file.
        """
        for filtered_file in glob.glob(f'{self.pcap_folder}/*.pcap'):
            filename = os.path.basename(filtered_file)
            label = filename.replace('.pcap', '')
            tshark_command = (
                f"tshark -r {filtered_file} -T fields "
                "-e ip.len -e ip.hdr_len -e ip.ttl -e ip.proto -e tcp.srcport -e tcp.dstport "
                "-e tcp.seq -e tcp.ack -e tcp.window_size_value -e tcp.hdr_len -e tcp.len "
                "-e tcp.stream -e tcp.urgent_pointer -e ip.flags -e ip.id -e ip.checksum "
                "-e tcp.flags -e tcp.checksum"
            )

            all_features = os.popen(tshark_command).read()
            all_features = all_features.replace('\t', ',')
            all_features_list = all_features.splitlines()

            with open(self.output_csv, 'a') as label_feature:
                for features in all_features_list:
                    label_feature.write(f"{label},{features}\n")


    def process(self):
        """
        The main method to run the entire pcap processing pipeline:
        - Initialize the CSV file.
        - Filter pcap files.
        - Extract features and save them to the CSV.
        """
        self.initialize_csv()
        self.extract_features()

    def get_csv(self):
        """
        Returns the path to the generated CSV file.

        :return: Path to the output CSV file.
        """
        return os.path.abspath(self.output_csv)