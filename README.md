﻿# OVPN_Auth

Program for OpenVPN username/password authentication.

Программа для реализации авторизации OpenVPN по логину/паролю.



## Использование.

Файл конфигурации OpenVPN на стороне сервера:
```
script-security 3
auth-user-pass-verify "config\\OVPN_Auth.exe" via-env
```

Файл конфигурации OpenVPN на стороне клиента:
```
auth-user-pass
```
или
```
auth-user-pass "config\\authpass"
```


Программа ищет файл паролей в папке, где находится _OVPN_Auth.exe_ с именем модуля программы и расширением _«.pwd»_.

Например, модуль программы: _«c:\Program Files\OpenVPN\config\OVPN_Auth_x64.exe»_

Соответствующий ему файл паролей будет иметь имя: _«c:\Program Files\OpenVPN\config\OVPN_Auth_x64.pwd»_




## Формат файла паролей.

Состоит из строк вида:

```
<логин>:<common name>:<хеш пароля>:<метка активности учетки>:<список ip/подсетей>
```

**_\<логин\>_** - имя пользователя, которое пользователь вводит по запросу OpenVPN GUI (или которое прописывается в файле, указанном в директиве `auth-user-pass`)

**_\<common name\>_** - "common name" из сертификата, используемого для подключения к OpenVPN.

**_\<хеш пароля\>_** - SHA-256 хеш пароля, который пользователь вводит по запросу OpenVPN GUI (или которое прописывается в файле, указанном в директиве `auth-user-pass`)
(хеш можно сгенерировать, например, с использованием сайтов подобным http://www.md5calc.com/ и т.п.).

**_\<метка активности учетки\>_** - может иметь значения:
* «1», «enabled», «enable» - учетная запись активна.
* «0», «disabled», «disable» или пустое значение - учетная запись отключена.

**_\<список ip/подсетей\>_** - Список ip/подсетей, с которых разрешается соединяться клиенту.

Задается указанием ip/подсетей через запятую (пробелы не допускаются).

Формат указания подсетей:
* 192.168.1.1 – единичный ip
* 192.168.0.0/16 – подсеть
* 192.168.1. – подсеть 192.168.1.0/24
* 192.168.1 – подсеть 192.168.1.0/24
* 192.168. – подсеть 192.168.0.0/16
* 192.168 – подсеть 192.168.0.0/16


Неиспользуемые элементы настроек можно опускать начиная с конца.

В файле паролей могут существовать строки, с одинаковыми учетными данными пользователей (логин, common name, хеш), но использоваться будет первая найденная.


**_Примеры:_**
```
user1:client01:a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3:0
user2:client01:b3a8e0e1f9ab1bfe3a36f231f676f78bb30a519d2b21e6c530c0eee8ebb4a5d0:1:192.168.1.1
user3:client01:15e2b0d3c33891ebb0f1ef609ec419420c20e320ce94c65fbc8c3312448eb225:1:10.10.
user4:client02:a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3:1:192.168.1.1,192.168.1.2,192.168.1.3
user5:client05:a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3:1:10.8,192.168.55.,10.10.10.0/24
user6:client55:a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3
```




## Коды ошибок

Программа возвращает следующие коды ошибок (можно отследить в логе OpenVPN):
* 2 - в блоке переменных окружения процесса не найдены необходимые переменные окружения или они имеют пустое значение ("username", "common_name", "password", "untrusted_ip").
* 3 - IP-адрес, переданный в переменной окружения "untrusted_ip", имеет неверный формат.
* 10 - неверное common name (см. настройку **_\<common name\>_** в файле паролей) - для введенного пользователем логина в сертификате используется другой "common name".
* 11 - неверный пароль (см. настройку **_\<хеш пароля\>_** в файле паролей).
* 12 - учетная запись отключена (см. настройку **_\<метка активности учетки\>_** в файле паролей).
* 13 - доступ запрещен для IP, с которого подключается пользователь (см. настройку **_\<список ip/подсетей\>_** в файле паролей).
* 14 - учетная запись не найдена (неверное имя пользователя) - запись с введенным пользовтелем логином не найдена в файле паролей.
* 100 - неизвестная ошибка.
* 200 - неизвестная ошибка.
* 201 - ошибка в формате файла паролей (неверный синтаксис опций).
* 250 - программа запущена в режиме проверки файла паролей на корректность.



## Режим проверки файла паролей на корректность

Запуск: **_OVPN_Auth.exe \<testdb|/testdb|-testdb|--testdb\>_**

Проверяет файл паролей на корректность формата.

