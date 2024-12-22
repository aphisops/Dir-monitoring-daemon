Celem usługi jest monitorowanie zmian plików w podanym katalogu. Program startowy otrzymuje
co najmniej dwa argumenty: ścieżkę źródłową i ścieżkę docelowa. Jeżeli któraś ze ścieżek nie jest
katalogiem program powraca natychmiast z komunikatem błędu. W przeciwnym wypadku staje
się demonem. Demon wykonuje następujące czynności:
• przy pierwszym uruchomieniu skanuje katalog w poszukiwaniu plików i tworzy strukturę danych
zawierającą ich aktualny stan (więcej poniżej);
• proces demon usypia domyślnie na pięć minut (czas spania można zmieniać przy pomocy
dodatkowego opcjonalnego argumentu);
• po obudzeniu skanuje ponownie katalog i porównuje aktualny stan plików ze stanem zapisanym
na starcie, wykonuje niezbędne operacje i usypia ponownie.
Możliwe jest natychmiastowe obudzenie się demona poprzez wysłanie mu sygnału SIGUSR1. Komunikaty
demona, jak informacja o każdej akcji typu uśpienie/obudzenie się (naturalne lub w wyniku sygnału)
czy wykonanie operacji na plikach, są przesyłane do logu systemowego (syslog). Operacje porównania
stanu działają wg następujących zasad:
• napotkanie nowego plik w monitorowanym katalogu powinno spowodować zalogowanie
informacji o nim do logu systemowego, podobnie w przypadku zniknięcia pliku istniejącego
na starcie;
• w przypadku zmiany daty modyfikacji lub rozmiaru istniejącego już pliku, jego nowa wersja
powinna być skopiowana do katalogu docelowego;
• demon powinien zaktualizować informacje o zmodyfikowanym pliku, aby przy kolejnym
obudzeniu nie trzeba było wykonać kopii (chyba że plik w katalogu źródłowym zostanie ponownie
zmieniony);
• pozycje, które nie są zwykłymi plikami są ignorowane (np. katalogi i dowiązania symboliczne);
• operacje kopiowania mają być wykonane za pomocą niskopoziomowych operacji read/write.
