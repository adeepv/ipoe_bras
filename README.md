# ipoe_bras
VVSina ipoe bras for linux

конфиг льётся с биллинга через проксю, она подключается по tcp и полученный ответ без разбора пересовывает в netlink сокет - поэтому я и сказал что нужен напильник 
конфиг описан структурой term_session_info см. term-nms-proxy/nl.h terminator/term.h

но перед заливкой самих сессий, надо влить подсети - см. struct term_subnet in term-nms-proxy/nl.h

загрузить всё это добро не получая биллинга можно двумя путями - либо написать парсер конфиг файла и ссыпать всё туда, либо забить статиком внутрь прокси.
P. S. : можно сделать какой-нибудь cmd или подсмотреть vtysh у зебры. Мне принципе незачем, но если сильно надо и будет время или заинтересуете можно и по колдовать ;)
