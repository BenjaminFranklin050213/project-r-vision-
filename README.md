# project-r-vision-
Типы объектов, которые присутствуют в файлах формата OVAL:
•	Определения уязвимостей (Vulnerability Definitions): Описания конкретных уязвимостей в программном обеспечении или операционной системе. Это может включать номера CVE (Common Vulnerabilities and Exposures), описания уязвимости, условия, при которых она проявляется, и другие подробности;
•	Информация об уязвимостях CVE (Common Vulnerabilities and Exposures): это информация, взятая из базы данных общеизвестных уязвимостей информационной безопасности, которая показывает на какие общеизвестные уязвимости направлена найденная уязвимость (прошу прощения за тавтологию);
•	Критерии (Criteria): Определения для проверки наличия или отсутствия уязвимостей на системе. Они могут включать в себя набор условий, которые должны быть выполнены для определения состояния безопасности, например, версии программного обеспечения, наличие определенных файлов и т.д;
•	Патчи (Patches): Описания патчей безопасности, необходимых для исправления уязвимостей или обеспечения безопасности системы. Это может включать информацию о версиях исправлений, ссылки на загрузку патчей и прочее;
•	Объекты системы (System Objects): Описания системных характеристик, таких как файлы, реестр, настройки системы и т.д. Эти объекты могут использоваться для проверки конфигураций системы на предмет соответствия безопасным стандартам.

 
Лишние критерии в определениях уязвимостей:
Подчеркну, что ЛИШНИХ критериев по моему мнению не бывает, все зависит от конкретного контекста безопасности и целей проверки ОС. Таких параметров в задании не задано. Видно, что критериев проверки этих уязвимостей чрезвычайно много, но в каждой уязвимости проверка направлена на определенные пакеты, а в некоторых уязвимостях на несколько пакетов и функций сразу. Из-за этих аспектов это задание вызывает трудности. Поэтому список лишних критериев скромен:
•	Так как проявляется нагромождение критериев формата "comment": "Red Hat Enterprise Linux 8 is installed", "comment": "Red Hat CoreOS 4 is installed" и т.д., которые указывают на наличие ПО Red Hat, в котором и проводился скан уязвимостей, информацию об установке этих ОС можно исключить. Эта информация содержится в генераторе в имени продукта;
•	По 3 уязвимости можно заметить, что происходит скан пакетов Ruby. Я считаю, что достаточно указать все модули этого пакета которые должны быть проверены на реализацию уязвимости