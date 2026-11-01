'use strict';
// Each row is key | Russian | Spanish. All UI keys are checked in app.test.cjs.
const extraLocales={ru:{},es:{}};
const localeRows=`workspace|ЛИЧНОЕ ПРОСТРАНСТВО|ESPACIO PERSONAL
workspaceLabel|РАБОЧАЯ ОБЛАСТЬ|ESPACIO DE TRABAJO
navDashboard|Обзор|Resumen
navProfiles|Профили и правила|Perfiles y reglas
navEngines|Каталог движков|Biblioteca de motores
navDiagnostics|Диагностика|Diagnóstico
navSettings|Настройки|Ajustes
preferences|ПАРАМЕТРЫ|PREFERENCIAS
privacy|Конфиденциальность|Privacidad
privacyText|В AccessWeaver нет аккаунтов и телеметрии. У внешних движков свои условия.|AccessWeaver no usa cuentas ni telemetría. Los motores externos tienen sus propias condiciones.
upstream|Исходные проекты ↗|Proyectos originales ↗
console|Панель|Panel
localOnly|ТОЛЬКО ЛОКАЛЬНО|SOLO LOCAL
networkWorkspace|СЕТЕВАЯ РАБОЧАЯ ОБЛАСТЬ|ESPACIO DE RED
welcome|Ваше подключение, ваши правила.|Tu conexión, tus reglas.
welcomeText|Профили, сетевые инструменты и диагностика в одном месте.|Perfiles, herramientas de red y diagnóstico en un solo lugar.
runDiagnostic|Запустить диагностику|Ejecutar diagnóstico
connectionOverview|ОБЗОР ПОДКЛЮЧЕНИЯ|RESUMEN DE CONEXIÓN
currentStatus|ТЕКУЩЕЕ СОСТОЯНИЕ|ESTADO ACTUAL
selectProfile|Выбрать профиль|Elegir perfil
manageProfiles|Управление профилями|Gestionar perfiles
noSilentChanges|Без скрытых изменений DNS и маршрутов|Sin cambios ocultos de DNS ni rutas
yourProfiles|ВАШИ ПРОФИЛИ|TUS PERFILES
profilesDesc|Редактируемые переносимые настройки|Configuraciones editables y portátiles
savedLocally|Сохранено локально|Guardado localmente
engineSupport|КАТАЛОГ ДВИЖКОВ|BIBLIOTECA DE MOTORES
engineDesc|Независимо устанавливаемые инструменты|Herramientas instaladas por separado
quickProfiles|Быстрый доступ к профилям|Acceso rápido a perfiles
quickProfilesText|Просматривайте и меняйте сохранённые настройки.|Consulta y modifica tus configuraciones guardadas.
viewAll|Все профили|Ver todos
controlTitle|Вы управляете изменениями|Tú controlas los cambios
controlText|AccessWeaver меняет систему только по явному запросу. Доступность движков зависит от платформы.|AccessWeaver cambia el sistema solo por solicitud explícita. Los motores disponibles dependen de la plataforma.
advancedTools|Дополнительные инструменты|Herramientas avanzadas
advancedText|CLI, JSON-профили и отчёты|CLI, perfiles JSON e informes
profilesTitle|Профили и правила|Perfiles y reglas
profilesSubtitle|Редактируйте стратегии, домены и пути к программам.|Edita estrategias, dominios y rutas de programas.
import|Импорт JSON|Importar JSON
createProfile|Создать профиль|Crear perfil
enginesTitle|Каталог движков|Biblioteca de motores
enginesSubtitle|Единый интерфейс для независимых сетевых инструментов.|Una interfaz para herramientas de red independientes.
externalTools|Независимые внешние инструменты|Herramientas externas independientes
externalNote|Движки не устанавливаются скрытно. Укажите официальный исполняемый файл. Правила зависят от адаптера.|Los motores no se instalan sin avisar. Indica el ejecutable oficial. Las reglas dependen del adaptador.
diagnosticsTitle|Диагностика подключения|Diagnóstico de conexión
diagnosticsSubtitle|Проверка DNS, TCP и TLS с проверкой сертификата.|Comprueba DNS, TCP y TLS con verificación del certificado.
newTest|Новая проверка|Nueva prueba de conexión
diagnosticNote|Проверки не меняют DNS, маршруты и настройки системы.|Las pruebas no modifican DNS, rutas ni ajustes del sistema.
hostname|Имя узла|Nombre del servidor
timeout|Тайм-аут (секунды)|Tiempo de espera (segundos)
verifyTLS|Проверять сертификат и соединение TLS|Verificar el certificado y la conexión TLS
startTest|Запустить проверку|Iniciar prueba
testResults|Результаты|Resultados
noResults|Проверок пока нет|Todavía no hay pruebas
noResultsText|Запустите проверку, чтобы увидеть этапы подключения.|Ejecuta una prueba para ver las etapas de conexión.
settingsTitle|Настройки|Ajustes
settingsSubtitle|Параметры интерфейса и среды выполнения.|Opciones de interfaz y entorno de ejecución.
language|Язык|Idioma
languageDesc|Выберите язык интерфейса. README по умолчанию на английском.|Elige el idioma de la interfaz. El README principal está en inglés.
appearance|Оформление|Apariencia
appearanceDesc|Выберите тёмную или светлую тему.|Elige el tema oscuro o claro.
environment|Среда выполнения|Entorno de ejecución
environmentDesc|Правила учитывают платформу. Права администратора не выдаются автоматически.|Las reglas dependen de la plataforma. Los privilegios no se elevan automáticamente.
repository|Проект и лицензии|Proyecto y licencias
repositoryDesc|Код AccessWeaver — 0BSD. У внешних движков свои лицензии.|El código de AccessWeaver usa 0BSD. Los motores externos conservan sus licencias.
runtimeLogs|Журнал работы|Actividad de ejecución
runtimeLogsDesc|Последний вывод движка хранится в памяти процесса.|La salida reciente del motor se conserva en la memoria del proceso.
viewLogs|Открыть журнал|Ver registros
footerText|Прозрачность и ваш выбор.|Transparencia y tus decisiones.
profileStudio|РЕДАКТОР ПРОФИЛЕЙ|EDITOR DE PERFILES
guidedEditor|Редактор полей|Editor guiado
jsonEditor|Редактор JSON|JSON avanzado
profileId|Идентификатор профиля|Identificador del perfil
displayName|Отображаемое имя|Nombre visible
description|Описание|Descripción
engine|Движок|Motor
category|Категория|Categoría
binaryPath|Исполняемый файл (полный путь или имя в PATH)|Ejecutable (ruta absoluta o nombre en PATH)
arguments|Аргументы (по одному в строке, без оболочки)|Argumentos (uno por línea, sin intérprete)
domainRules|Правила доменов|Reglas de dominios
includedDomains|Включённые домены (по одному в строке)|Dominios incluidos (uno por línea)
excludedDomains|Исключённые домены (по одному в строке)|Dominios excluidos (uno por línea)
rulesWarning|Примеры не охватывают весь трафик приложений. Неподдерживаемые правила блокируют запуск.|Los ejemplos no cubren todo el tráfico de las aplicaciones. Las reglas no compatibles bloquean el inicio.
moreOptions|Приложения и проверка целостности|Aplicaciones e integridad
apps|Имена приложений или папки (WireSock)|Nombres de aplicaciones o carpetas (WireSock)
probeHost|Узел для проверки|Servidor de prueba
probePort|Порт проверки|Puerto de prueba
probeTLS|Проверять сертификат TLS|Verificar certificado TLS
notes|Примечания|Notas
jsonHelp|Неизвестные поля и неверные значения отклоняются до сохранения.|Los campos desconocidos y valores incorrectos se rechazan antes de guardar.
cancel|Отмена|Cancelar
saveChanges|Сохранить изменения|Guardar cambios
recentLogs|Последний вывод движка|Registros recientes del motor
logsVolatile|Показаны последние записи из памяти процесса.|Se muestran los registros recientes de la memoria del proceso.
copyLogs|Копировать журнал|Copiar registros
ready|Готово к настройке|Listo para configurar
readyDesc|Выберите профиль. Ничего не запускается автоматически.|Elige un perfil. Nada se inicia automáticamente.
running|Процесс запущен|Proceso en ejecución
runningDesc|Процесс движка активен. Маршрутизацию и связь нужно проверить отдельно.|El proceso está activo. Verifica la conexión y el enrutamiento por separado.
offline|Автономный редактор|Editor sin conexión
offlineDesc|Можно редактировать и экспортировать профили. Для запуска нужен локальный сервер.|Puedes editar y exportar perfiles. Para ejecutar motores necesitas el núcleo local.
notRunning|НЕ ЗАПУЩЕНО|DETENIDO
runningBadge|ПРОЦЕСС АКТИВЕН|PROCESO ACTIVO
offlineBadge|ТОЛЬКО РЕДАКТОР|SOLO EDITOR
edit|Изменить|Editar
start|Запустить|Iniciar
stop|Остановить|Detener
duplicate|Создать копию|Duplicar
export|Экспорт|Exportar
delete|Удалить|Eliminar
allEngines|Все движки|Todos los motores
searchProfiles|Поиск профилей, движков и примечаний…|Buscar perfiles, motores y notas…
profilesShown|профилей|perfiles
saved|Профиль сохранён|Perfil guardado
imported|Профиль импортирован|Perfil importado
deleted|Профиль удалён|Perfil eliminado
created|Профиль создан|Perfil creado
confirmDelete|Удалить профиль? Это действие нельзя отменить.|¿Eliminar el perfil? No se puede deshacer.
confirmStart|Запустить внешний движок? Проверьте файл и аргументы. Могут потребоваться права администратора.|¿Iniciar el motor externo? Revisa el archivo y los argumentos. Puede requerir privilegios de administrador.
startFailed|Не удалось запустить|No se pudo iniciar
stopped|Движок остановлен|Motor detenido
startOk|Процесс запущен. Проверьте подключение.|Proceso iniciado. Verifica la conexión.
engineUnsupported|Не поддерживается здесь|No compatible aquí
engineSupported|Платформа указана|Plataforma incluida
readDocs|Исходный код и документация ↗|Código y documentación ↗
noProfiles|Профили не найдены. Создайте новый.|No hay perfiles coincidentes. Crea uno nuevo.
missingServer|Локальный сервер недоступен. Доступен только редактор профилей.|El núcleo local no está disponible. Solo puedes editar perfiles.
editorTitleNew|Создать профиль|Crear perfil
editorTitleEdit|Изменить профиль|Editar perfil
savedOffline|Сохранено только в этом браузере|Guardado solo en este navegador
testRunning|Проверка…|Probando…
testDone|Проверка завершена|Prueba terminada
testFailed|Проверка не пройдена|Prueba fallida
jsonError|Некорректный JSON|JSON incorrecto
importInvalid|Не удалось импортировать JSON-профиль|No se pudo importar el perfil JSON
settingsLogsEmpty|Вывод движка ещё не получен.|Todavía no hay salida del motor.
copySuccess|Скопировано|Copiado
unsupportedRules|Адаптер не применяет эти правила автоматически.|El adaptador no aplica estas reglas automáticamente.
skipContent|Перейти к содержимому|Saltar al contenido
configurationStudio|РЕДАКТОР НАСТРОЕК|EDITOR DE CONFIGURACIÓN
integrationCatalog|КАТАЛОГ ИНТЕГРАЦИЙ|CATÁLOGO DE INTEGRACIONES
networkIntelligence|ДИАГНОСТИКА СЕТИ|DIAGNÓSTICO DE RED
yourEnvironment|ВАША СРЕДА|TU ENTORNO
runtimeLabel|ВЫПОЛНЕНИЕ|EJECUCIÓN
filterEngine|Фильтр по движку|Filtrar por motor
tcpPort|Порт TCP|Puerto TCP
midnight|Тёмная|Oscuro
daylight|Светлая|Claro
toggleNavigation|Открыть или закрыть меню|Abrir o cerrar menú
toggleTheme|Сменить тему|Cambiar tema
close|Закрыть|Cerrar
profileJSON|JSON профиля|JSON del perfil
checksum|SHA-256 исполняемого файла (необязательно)|SHA-256 del ejecutable (opcional)
profileStorage|Хранение профилей|Almacenamiento de perfiles
coreStorage|Профили сохраняет локальный сервер. Параметры интерфейса остаются в браузере.|El núcleo local guarda los perfiles. Las preferencias de interfaz quedan en el navegador.
browserStorage|Профили хранятся только в браузере. Экспортируйте их перед очисткой данных.|Los perfiles se guardan solo en este navegador. Expórtalos antes de borrar sus datos.
coreStorageBadge|ЛОКАЛЬНЫЙ СЕРВЕР|NÚCLEO LOCAL
browserStorageBadge|ЭТОТ БРАУЗЕР|ESTE NAVEGADOR
reconnect|Подключиться снова|Reconectar
disconnected|Связь с сервером потеряна|Núcleo desconectado
disconnectedDesc|Последнее состояние устарело. Подключитесь снова, чтобы продолжить.|El último estado no está actualizado. Reconecta para continuar.
disconnectedNotice|Связь с локальным сервером потеряна. Несохранённые изменения остаются в редакторе.|Se perdió la conexión con el núcleo. Los cambios sin guardar permanecen en el editor.
offlineNotice|Редактор браузера. Для запуска движков и диагностики нужен локальный сервер.|Editor del navegador. Necesitas el núcleo local para ejecutar motores y diagnósticos.
connecting|Подключение к локальному серверу…|Conectando con el núcleo local…
connectedAgain|Связь с сервером восстановлена|Conexión local restablecida
switchStore|Локальный сервер доступен. Сначала экспортируйте нужные браузерные профили. Переключиться?|El núcleo local está disponible. Exporta primero los perfiles del navegador que necesites. ¿Cambiar ahora?
storageFailed|Хранилище браузера недоступно или заполнено. Изменения не сохранены. Экспортируйте профиль.|El almacenamiento está lleno o no está disponible. No se guardaron los cambios. Exporta el perfil.
platformCoverage|Поддержка платформ|Compatibilidad de plataformas
platformCoverageDesc|У сервера и движков разные требования.|El núcleo y los motores tienen requisitos distintos.
desktopCore|Локальный сервер|Núcleo local
partialCore|Некоторые движки|Motores seleccionados
mobileEditor|Браузерный редактор|Editor del navegador
windowsSupport|Управление локальными движками. Могут потребоваться WinDivert и права администратора.|Gestión de motores locales. Puede requerir WinDivert y privilegios de administrador.
linuxSupport|Для пакетных движков нужны отдельно настроенные правила перехвата.|Los motores de paquetes requieren reglas de captura configuradas por separado.
macSupport|Поддерживаются некоторые прокси. Перехват пакетов и туннели ограничены.|Se admiten algunos proxies. La captura de paquetes y los túneles son limitados.
bsdSupport|Проверьте вариант BSD, сборку движка и правила перехвата.|Comprueba la variante BSD, la compilación y las reglas de captura.
androidSupport|Это браузерный редактор. Для VPN нужен отдельный клиент Android.|Este es un editor del navegador. La VPN requiere un cliente Android separado.
iosSupport|iOS не запускает эти настольные движки. Нужен отдельный разрешённый VPN-клиент.|iOS no ejecuta estos motores de escritorio. Necesitas un cliente VPN autorizado aparte.
managedIntegration|УПРАВЛЯЕМЫЙ ПРОЦЕСС|PROCESO GESTIONADO
externalIntegration|ВНЕШНЯЯ НАСТРОЙКА|CONFIGURACIÓN EXTERNA
includesLabel|Включения|Inclusiones
excludesLabel|Исключения|Exclusiones
appRules|Правила приложений|Reglas de aplicaciones
supportedRule|Применяется|Se aplica
unsupportedRule|Внешняя настройка / не поддерживается|Externo / no compatible
createForEngine|Создать профиль|Crear perfil
setupRequired|Нужна настройка|Requiere configuración
engineAvailable|Совместимая платформа|Plataforma compatible
engineExternal|Внешнее управление|Gestión externa
platformUnknown|Проверьте платформу|Comprueba la plataforma
engineSource|Официальный проект|Proyecto oficial
engineDocs|Инструкция по настройке|Instrucciones de configuración
noArguments|Дополнительных аргументов нет|Sin argumentos adicionales
configPath|Внешний файл конфигурации (полный путь)|Archivo de configuración externo (ruta absoluta)
configPathHelp|Требуется WireSock, sing-box и Xray. Исходный файл не изменяется.|Necesario para WireSock, sing-box y Xray. El archivo original no se modifica.
exclusionExamples|Добавить примеры исключений:|Añadir ejemplos de exclusión:
windowsUpdate|Windows Update|Windows Update
supportedIncludes|Адаптер применяет включённые домены.|El adaptador aplica los dominios incluidos.
unsupportedIncludes|Адаптер не применяет включённые домены.|El adaptador no aplica los dominios incluidos.
supportedExcludes|Адаптер применяет исключённые домены.|El adaptador aplica los dominios excluidos.
unsupportedExcludes|Адаптер не применяет исключённые домены.|El adaptador no aplica los dominios excluidos.
appRulesNote|Правила WireSock записываются в отдельную конфигурацию. Для ProxiFyre и Secure Connect 3.x используйте раздел установки.|Las reglas WireSock se escriben en una configuración privada. Usa Instalación y reparación para ProxiFyre y Secure Connect 3.x.
addedExclusions|Примеры добавлены. Проверьте их область действия.|Ejemplos añadidos. Revisa su alcance.
includeCount|включено|incluidos
excludeCount|исключено|excluidos
preview|Проверить настройку|Comprobar configuración
launchReview|ПРОВЕРКА ЗАПУСКА|REVISIÓN DE INICIO
reviewSetup|Проверка настройки движка|Revisar configuración del motor
editProfile|Изменить профиль|Editar perfil
startEngine|Запустить движок|Iniciar motor
launchConsent|Внешняя программа получит ваши текущие права. Сначала проверьте файл, аргументы и конфигурацию.|El programa externo usará tus privilegios actuales. Revisa primero el archivo, los argumentos y la configuración.
launchNotConnectivity|Готовность не подтверждает работоспособность подключения.|Estar listo no confirma que la conexión funcione.
checkingSetup|Проверка программы и профиля…|Comprobando programa y perfil…
setupReady|Предварительные условия выполнены|Requisitos de inicio encontrados
setupBlocked|Устраните проблемы перед запуском|Resuelve los problemas antes de iniciar
executable|Исполняемый файл|Ejecutable
launchArguments|Список аргументов без оболочки|Lista de argumentos sin intérprete
workingDirectory|Рабочая папка|Carpeta de trabajo
warnings|Примечания к проверке|Notas de revisión
issues|Проблемы настройки|Problemas de configuración
previewUnavailable|Для проверки нужен локальный сервер.|La comprobación requiere el núcleo local.
readyToConfigure|Настройте и проверьте|Configura y comprueba
guideSpoof|Используйте совместимый HTTP-прокси. Проверьте, меняет ли он системные настройки прокси.|Usa un proxy HTTP compatible. Comprueba si cambia los ajustes de proxy del sistema.
guideByedpi|Локальный SOCKS-прокси. Настройте приложение отдельно: запуск не перенаправляет весь компьютер.|Proxy SOCKS local. Configura cada aplicación: iniciarlo no redirige todo el equipo.
guideZapret|Нужны совместимые драйверы или правила перехвата и проверенная стратегия.|Se requieren controladores o reglas de captura compatibles y una estrategia probada.
guideGoodbye|Обработка пакетов Windows через WinDivert. Включения поддерживаются, исключения — нет.|Procesamiento de paquetes Windows con WinDivert. Admite inclusiones, pero no exclusiones.
guideWiresock|SDK использует внешний конфиг. Secure Connect 3.x управляется в разделе установки. У производителя свои условия лицензии и телеметрии.|El SDK usa una configuración externa. Gestiona Secure Connect 3.x desde Instalación. El proveedor tiene sus propias condiciones y telemetría.
guideWireguard|Управляйте туннелем официальным клиентом платформы. Здесь профиль только хранится.|Gestiona el túnel con el cliente oficial de la plataforma. Aquí solo se guarda el perfil.
guideProxy|Укажите установленный файл и совместимую конфигурацию. Маршрутизацию настройте отдельно.|Indica el ejecutable instalado y una configuración compatible. Configura el enrutamiento por separado.
discardChanges|Отменить несохранённые изменения?|¿Descartar los cambios sin guardar?
duplicateId|Этот идентификатор уже существует. Выберите другой или измените существующий профиль.|El identificador ya existe. Elige otro o edita el perfil existente.
immutableId|Нельзя менять ID сохранённого профиля. Создайте копию.|No puedes cambiar el ID de un perfil guardado. Duplícalo.
invalidProfile|Файл должен содержать один объект профиля.|El archivo debe contener un único objeto de perfil.
unknownField|Неизвестное поле|Campo desconocido
invalidField|Неверное значение поля|Valor incorrecto en
requiredField|Обязательное поле|Campo obligatorio
invalidVersion|Версия профиля должна быть 1.|La versión del perfil debe ser 1.
invalidId|От 2 до 63 строчных латинских букв, цифр и дефисов; первая — буква.|Usa de 2 a 63 letras minúsculas, dígitos o guiones; empieza con una letra.
invalidEngine|Выберите движок из каталога.|Elige un motor de la biblioteca.
invalidDomain|Укажите домен ASCII/IDNA без URL и пробелов.|Indica un dominio ASCII/IDNA sin URL ni espacios.
duplicateDomain|Повторяющийся домен|Dominio duplicado
conflictingDomain|Домен не может быть одновременно включён и исключён|Un dominio no puede estar incluido y excluido a la vez
invalidSHA|SHA-256 должен содержать 64 шестнадцатеричных символа.|SHA-256 debe contener 64 caracteres hexadecimales.
fileTooLarge|Размер файла превышает 1 МиБ.|El archivo supera 1 MiB.
importReview|Проверьте и сохраните импортированный профиль. Существующие профили сохранены.|Revisa y guarda el perfil importado. Se conservan los perfiles existentes.
importRenamed|ID уже существует. Назначен новый: проверьте и сохраните копию.|El ID ya existe. Se asignó uno nuevo: revisa y guarda la copia.
saving|Сохранение…|Guardando…
unsavedChanges|Несохранённые изменения|Cambios sin guardar
newProfileName|Мой профиль|Mi perfil
customCategory|Пользовательский|Personalizado
copySuffix|копия|copia
defaultDescription|Редактируемая конфигурация движка|Configuración editable del motor
activeEdit|Перед изменением остановите активный профиль.|Detén el perfil activo antes de editarlo.
otherRunning|Перед запуском другого профиля остановите текущий.|Detén el perfil actual antes de iniciar otro.
coreRequired|Нужно подключение к локальному серверу.|Esta acción requiere conexión con el núcleo local.
failedState|Движок завершился|El motor terminó
failedDesc|Движок не работает. Проверьте вывод и настройку перед перезапуском.|El motor está detenido. Revisa la salida y la configuración antes de reiniciarlo.
exitError|Вывод движка|Salida del motor
exportReport|Экспорт отчёта|Exportar informe
reportHost|Проверенный узел|Servidor probado
testPassed|Все запрошенные проверки пройдены|Se superaron todas las comprobaciones
testIncomplete|Одна или несколько проверок не пройдены|Falló una o más comprobaciones
noProbe|Нет отчёта для экспорта|No hay informe para exportar
argsPrecision|Один аргумент на строку. Пробелы и пустые аргументы JSON сохраняются.|Un argumento literal por línea. Se conservan los espacios y argumentos vacíos de JSON.
profileSaved|Профиль сохранён|Perfil guardado
loading|Загрузка…|Cargando…
refreshLogs|Обновить журнал|Actualizar registros
storageRecovery|Некоторые профили не читаются, но сохранены. Экспортируйте резервную копию в настройках.|Algunos perfiles no se pueden leer, pero se conservan. Exporta una copia desde Ajustes.
exportBrowserBackup|Экспорт резервной копии браузера|Exportar copia del navegador
storageUnreadable|JSON в хранилище повреждён и сохранён. Экспортируйте копию перед восстановлением.|El JSON almacenado no se puede leer y se ha conservado. Exporta una copia antes de repararlo.
supportSummary|Сводка для поддержки|Resumen de soporte
exportSupportSummary|Экспорт сводки для поддержки|Exportar resumen de soporte
supportSummaryDesc|Экспорт версии сборки, количества профилей и меток состояния. Содержимое и идентификаторы профилей, пути, журналы и учётные данные не включаются. Ничего не отправляется.|Exporta la identidad de compilación, recuentos y estados. Excluye contenidos e identificadores de perfiles, rutas, registros y credenciales. No se sube nada.
systemTools|Установка и восстановление|Instalación y reparación
systemSubtitle|Методы доступа, правила приложений и восстановление системы.|Métodos de acceso, reglas de aplicaciones y recuperación del sistema.
inspectSystem|Проверить систему|Inspeccionar sistema
systemBoundary|Не запускайте панель с правами администратора. Проверьте изменения здесь и примените запрос отдельно командой system apply с повышенными правами. Службы продолжают работать после закрытия панели.|Mantén el panel sin privilegios elevados. Revisa los cambios aquí y aplica la solicitud con system apply en una consola elevada por separado. Los servicios siguen activos al cerrar el panel.
exportSystemRequest|Экспорт проверенного запроса|Exportar solicitud revisada
exportSystemRequestNote|Файл запроса может содержать частные пути или аргументы. Храните его в защищённом месте, повторно проверьте в командной строке и подтвердите отдельно.|El archivo puede contener rutas o argumentos privados. Guárdalo de forma privada, revísalo de nuevo en la consola y confírmalo por separado.
operation|Операция|Operación
component|Компонент или приложение|Componente o aplicación
setupMode|Режим установки|Modo de instalación
pureTunnel|Альтернативный: только WireSock|Alternativo: solo WireSock
combinedTunnel|Стандартный: WireSock и ByeDPI DLL|Estándar: WireSock y ByeDPI DLL
customSetup|Выбранные приложения|Aplicaciones personalizadas
splitSetup|ByeDPI и ProxiFyre|ByeDPI y ProxiFyre
dllSetup|ByeDPI DLL для Discord|ByeDPI DLL para Discord
persistentService|Постоянная служба|Servicio persistente
presetCollection|Готовая стратегия|Estrategia predefinida
customArguments|Свои аргументы|Argumentos personalizados
applicationSelection|Дополнительные приложения или папки (по одному в строке)|Aplicaciones o carpetas adicionales (una por línea)
includeBrowsers|Включить браузеры|Incluir navegadores
periodicReconnect|Периодически переподключать WireSock|Reconexión periódica de WireSock
dnsMethod|Метод DNS|Método DNS
leaveDNS|Сохранить текущий DNS|Conservar DNS actual
scanLevel|Уровень поиска стратегии|Nivel de búsqueda de estrategia
quickScan|Быстрый|Rápido
standardScan|Стандартный|Estándar
fullScan|Полный|Completo
enableListTask|Включить список доменов или задачу обновления|Activar lista de dominios o tarea de reconexión
cleanPTB|Удалить обычный Discord при установке PTB|Eliminar Discord estable al instalar PTB
componentPaths|Пути компонентов и загрузки|Rutas y descargas de componentes
componentBundle|Папка готового набора компонентов (необязательно)|Carpeta del paquete de componentes (opcional)
privateConfig|Существующая конфигурация WireGuard (необязательно)|Configuración WireGuard existente (opcional)
managedProfile|Имя управляемого профиля|Nombre del perfil gestionado
officialDownload|Официальный URL загрузки (необязательно)|URL oficial de descarga (opcional)
reviewOperation|Проверить операцию|Revisar operación
operationReview|Проверка операции|Revisión de la operación
confirmSystemChanges|Операция и изменения системы проверены|He revisado la operación y sus cambios en el sistema
applyOperation|Выполнить проверенную операцию|Aplicar operación revisada
cancelOperation|Отменить текущую операцию|Cancelar operación en curso
operationHistory|История операций|Historial de operaciones
chooseFolder|Добавить папку|Añadir carpeta
clearApplications|Очистить список приложений|Vaciar lista de aplicaciones
scanTargets|Узлы для проверки (по одному в строке)|Destinos de prueba (uno por línea)
recoveryJournal|Имя файла журнала восстановления|Nombre del registro de recuperación
onceMode|Однократный запуск|Ejecución única
operationResult|Результат и восстановление|Resultado y recuperación
cloudflareTerms|Я принимаю условия Cloudflare для регистрации нового аккаунта WARP|Acepto las condiciones de Cloudflare para registrar una cuenta WARP nueva`;
for(const row of localeRows.split('\n')){const [key,ru,es]=row.split('|');if(!key||!ru||!es)throw new Error('Invalid translation row');extraLocales.ru[key]=ru;extraLocales.es[key]=es;}
const systemOperationText={};
const operationRows=`discover|Inspect installed tools|Kurulu araçları incele|Проверить установленные инструменты|Inspeccionar herramientas instaladas
download|Download a component|Bileşen indir|Скачать компонент|Descargar componente
install|Install an access method|Erişim yöntemi kur|Установить способ доступа|Instalar método de acceso
config|Generate WireSock configuration|WireSock yapılandırması oluştur|Создать конфигурацию WireSock|Generar configuración WireSock
connect|Connect WireSock|WireSock bağlan|Подключить WireSock|Conectar WireSock
disconnect|Disconnect WireSock|WireSock bağlantısını kes|Отключить WireSock|Desconectar WireSock
scan|Find a Zapret strategy|Zapret stratejisi bul|Найти стратегию Zapret|Buscar estrategia Zapret
auto-install|Find and install a strategy|Strateji bul ve kur|Найти и установить стратегию|Buscar e instalar estrategia
hostlist|Save or toggle hostlist|Alan adı listesini kaydet veya aç/kapat|Сохранить или переключить список доменов|Guardar o activar lista de dominios
dns|Configure encrypted DNS|Şifreli DNS yapılandır|Настроить зашифрованный DNS|Configurar DNS cifrado
dns-restore|Restore original DNS|Özgün DNS ayarlarını geri yükle|Восстановить исходный DNS|Restaurar DNS original
refresh|Configure periodic reconnect|Düzenli yeniden bağlantıyı ayarla|Настроить периодическое подключение|Configurar reconexión periódica
remove|Remove a managed method|Yönetilen yöntemi kaldır|Удалить управляемый метод|Eliminar método gestionado
vendor-uninstall|Uninstall WireSock product|WireSock ürününü kaldır|Удалить продукт WireSock|Desinstalar producto WireSock
remove-all|Remove all managed methods|Yönetilen tüm yöntemleri kaldır|Удалить все управляемые методы|Eliminar todos los métodos gestionados
app-install|Install Discord variant|Discord sürümü kur|Установить вариант Discord|Instalar variante de Discord
app-start|Start Discord variant|Discord sürümünü başlat|Запустить вариант Discord|Iniciar variante de Discord
app-remove|Uninstall Discord variant|Discord sürümünü kaldır|Удалить вариант Discord|Desinstalar variante de Discord
app-repair|Repair Discord|Discord onar|Восстановить Discord|Reparar Discord
updates|Check for updates|Güncellemeleri denetle|Проверить обновления|Buscar actualizaciones
uninstall|Uninstall AccessWeaver|AccessWeaver kaldır|Удалить AccessWeaver|Desinstalar AccessWeaver
recover|Recover an interrupted operation|Yarım kalan işlemi geri al|Восстановить прерванную операцию|Recuperar operación interrumpida`;
for(const row of operationRows.split('\n')){const [id,en,tr,ru,es]=row.split('|');systemOperationText[id]={en,tr,ru,es};}

extraLocales.ru.updateAvailable='Доступно обновление';
extraLocales.es.updateAvailable='Actualización disponible';
