#include <iostream>

extern void run_client();
extern void run_server();

int main(int argc, char *argv[])
{
    std::cout << "Starting " << std::endl;

    if (argc > 1)
    {
        if (strcmp(argv[1], "server") == 0)
        {
            run_server();
        }
        else if (strcmp(argv[1], "client") == 0)
        {
            run_client();
        }
        else
        {
            std::cout << "unknow function." << std::endl;
        }
    }
    else
    {
        std::cout << "server or client argument needed." << std::endl;
        return -1;
    }

    return 0;
}
