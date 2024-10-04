#include <iostream>
#include <pcap.h>
#include <cstring>
#include <cstdlib>
#include <netinet/ip.h> //ip
#include <netinet/tcp.h> //tpc
#include <arpa/inet.h> //преобр.ip

using namespace std;

//Для командной строки
struct FilterArgs 
{
    const char *filename; //файл
    const char *srcaddr = nullptr; //исх.ip
    const char *dstaddr = nullptr; //цел.ip
    const char *srcport = nullptr; //исх.прт
    const char *dstport = nullptr; //цел.прт
    
    //Для подсчета статиистики
    int totalPackets = 0;     // Общее количество пакетов
    int tcpPackets = 0;       // Общее количество TCP-пакетов
    int filteredPackets = 0;  // Число пакетов, попадающих под фильтры
};

//Разбор аргументов командной строки
FilterArgs parseArgs(int argc, char *argv[]) 
{
    FilterArgs args;

    if (argc < 2) 
	{
        cerr << "Использование: " << argv[0] << " <pcap файл> [--srcaddr <ip>] [--dstaddr <ip>] [--srcport <port>] [--dstport <port>]" << endl;
        exit(EXIT_FAILURE);
    }

    args.filename = argv[1];

    //обработка для фильтра
    for (int i = 2; i < argc; i++) 
	{
        if (strcmp(argv[i], "--srcaddr") == 0 && i + 1 < argc) 
		{
            args.srcaddr = argv[++i];
        } else if (strcmp(argv[i], "--dstaddr") == 0 && i + 1 < argc) 
		{
            args.dstaddr = argv[++i];
        } else if (strcmp(argv[i], "--srcport") == 0 && i + 1 < argc) 
		{
            args.srcport = argv[++i];
        } else if (strcmp(argv[i], "--dstport") == 0 && i + 1 < argc) 
		{
            args.dstport = argv[++i];
        }
    }

    return args;
}

//обработки пакетов
void packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) 
{
    //аrgs к типу FilterArgs
    FilterArgs *filterArgs = (FilterArgs *)args;
    filterArgs->totalPackets++;

    //IP
    struct ip *ipHeader = (struct ip *)(packet + 14);

    //является ли пакет TCP
    if (ipHeader->ip_p == IPPROTO_TCP) 
	{
        filterArgs->tcpPackets++;

        //TCP
        struct tcphdr *tcpHeader = (struct tcphdr *)(packet + 14 + ipHeader->ip_hl * 4);
        
        //ip и порты
        char srcIP[INET_ADDRSTRLEN];
        char dstIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ipHeader->ip_src, srcIP, sizeof(srcIP));
        inet_ntop(AF_INET, &ipHeader->ip_dst, dstIP, sizeof(dstIP));

        bool match = true;

        //ip(исх.цел)
        if (filterArgs->srcaddr && strcmp(filterArgs->srcaddr, srcIP) != 0) 
		{
            match = false;
        }
        if (filterArgs->dstaddr && strcmp(filterArgs->dstaddr, dstIP) != 0) 
		{
            match = false;
        }

        //порты(исх.цел)
        if (filterArgs->srcport && strcmp(filterArgs->srcport, to_string(ntohs(tcpHeader->th_sport)).c_str()) != 0) 
		{
            match = false;
        }
        if (filterArgs->dstport && strcmp(filterArgs->dstport, to_string(ntohs(tcpHeader->th_dport)).c_str()) != 0) 
		{
            match = false;
        }

        if (match) 
		{
            filterArgs->filteredPackets++;
        }
    }
}

int main(int argc, char *argv[]) 
{
    FilterArgs args = parseArgs(argc, argv);

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    //pcap файл
    handle = pcap_open_offline(args.filename, errbuf);
    if (handle == nullptr) 
	{
        cerr << "Не удалось открыть файл: " << errbuf << endl;
        return 1;
    }

    pcap_loop(handle, 0, packetHandler, (u_char *)&args);

    pcap_close(handle);

    cout << "Общее число пакетов: " << args.totalPackets << endl;
    cout << "Общее число TCP-пакетов: " << args.tcpPackets << endl;
    cout << "Число TCP-пакетов по фильтрам: " << args.filteredPackets << endl;

    return 0;
}