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
shutdownPending|Завершение не подтверждено|Cierre sin confirmar
shutdownPendingDesc|Остановка предыдущего движка не подтверждена. Запуск другого движка заблокирован. Можно редактировать профили и просматривать журналы.|No se ha confirmado que el motor anterior esté detenido. El inicio de otro motor está bloqueado. Puedes seguir editando perfiles y consultar los registros.
shutdownPendingBadge|ЗАВЕРШЕНИЕ НЕ ПОДТВЕРЖДЕНО|CIERRE SIN CONFIRMAR
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
jsonPreviewLimited|Предпросмотр сокращён. Экспортируйте соответствующий JSON, чтобы прочитать все сведения.|Vista previa abreviada. Exporta el JSON correspondiente para leer todos los detalles.
exportSystemStatus|Экспорт текущего состояния|Exportar estado actual
exportSystemHistory|Экспорт полной истории|Exportar historial completo
systemExportPrivacy|Эти файлы могут содержать частную конфигурацию, пути и вывод инструментов. Храните их в защищённом месте. Ничего не отправляется.|Estos archivos pueden contener configuración, rutas y salida de herramientas privadas. Guárdalos de forma privada. No se sube nada.
systemExportFailed|Не удалось экспортировать этот отчёт.|No se pudo exportar este informe.
systemExportTooLarge|Отчёт превышает допустимый размер загрузки.|El informe supera el límite de tamaño de descarga.
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

Object.assign(extraLocales.ru,{"historyLargePreview":"Эта запись слишком велика для просмотра в приложении. Скачайте исходную запись, чтобы изучить все байты конфиденциально.","historyTitle":"История операций","historyCaptureNotice":"Перед просмотром создайте частный снимок метаданных истории. Записи и данные восстановления не удаляются.","historyCapture":"Создать снимок истории","historyRefresh":"Обновить просмотр","historyRecord":"Запись","historyState":"Состояние","historyTime":"Время записи","historySize":"Размер","historyClassification":"Тип записи","historyProtection":"Защита","historyPrevious":"Предыдущая страница","historyNext":"Следующая страница","historyRawPrivacy":"Исходные записи могут содержать частные настройки, пути, ошибки и вывод программ. Ничего не отправляется. Храните загруженные файлы конфиденциально.","historyExportRecord":"Скачать исходную запись","historyProtected":"Данные восстановления защищены. Удаление записей недоступно.","historyUnknown":"Неизвестно","historyBytes":"байт","historyLegacyRecord":"Сохранённая запись","historyUnknownOperation":"Неизвестная операция","historyNoCapture":"Снимок истории не загружен. Существующие записи не изменены.","historyInventorySummary":"Снимок: {count} объектов, {size}. Создан: {at}.","historyPageSummary":"Показано объектов из снимка: {count}.","historyEmpty":"В этом снимке нет объектов.","historyDetailTitle":"Запись: {record}","historyDetailLoading":"Загрузка выбранной записи…","historyRawUnavailable":"Этот объект нельзя безопасно прочитать как обычную запись допустимого размера. Данные остаются неизменными.","historyDetailUnavailable":"Структурированный просмотр недоступен. Скачайте исходную запись для частного изучения.","historyCapturing":"Создание частного снимка метаданных… Существующие данные не удаляются.","historyLoading":"Загрузка снимка истории…","historyCaptureNeeded":"Нужен новый снимок истории. Нажмите «Создать снимок истории»; записи останутся неизменными.","historyRecordUnavailable":"Выбранная запись недоступна. Создайте новый снимок для проверки её состояния.","historyRequestEnded":"Запрос истории завершился раньше времени. Повторите попытку; записи не удалены.","historyCapacity":"История превышает ограничения просмотра. Все записи и данные восстановления сохранены.","historyBusy":"История занята. Повторите попытку позже; операции не повторяются автоматически.","historyInvalidResponse":"Ответ истории не удалось проверить. Файл для скачивания не создан.","historyFailed":"Не удалось прочитать историю. Записи и данные восстановления не изменены.","historyClass_canonical":"Распознанная запись","historyClass_legacy":"Запись старого формата","historyClass_malformed":"Некорректная запись JSON","historyClass_oversized":"Превышен предел просмотра","historyClass_special":"Неподдерживаемый тип файла","historyClass_unreadable":"Нечитаемая запись","historyState_running":"Выполняется","historyState_succeeded":"Успешно","historyState_failed":"Ошибка","historyState_interrupted":"Прервано","historyState_unknown":"Неизвестно","historyCancelCapture":"Отменить запрос снимка","historyCaptureCanceled":"Запрос снимка отменён. Записи и данные восстановления не изменены. Обновите просмотр, чтобы проверить сохранённые метаданные."});
Object.assign(extraLocales.es,{"historyLargePreview":"Este registro es demasiado grande para la vista previa. Descarga el registro original exacto para examinar todos los bytes de forma privada.","historyTitle":"Historial de operaciones","historyCaptureNotice":"Captura los metadatos privados del historial antes de consultarlo. No se eliminan registros ni pruebas de recuperación.","historyCapture":"Capturar historial","historyRefresh":"Recargar captura","historyRecord":"Registro","historyState":"Estado","historyTime":"Fecha registrada","historySize":"Tamaño","historyClassification":"Tipo de registro","historyProtection":"Protección","historyPrevious":"Página anterior","historyNext":"Página siguiente","historyRawPrivacy":"Los registros originales pueden contener configuración, rutas, errores y salidas privadas. No se sube nada. Guarda las descargas de forma privada.","historyExportRecord":"Descargar registro original exacto","historyProtected":"Las pruebas de recuperación están protegidas. La retirada de registros no está disponible.","historyUnknown":"Desconocido","historyBytes":"bytes","historyLegacyRecord":"Registro conservado","historyUnknownOperation":"Operación desconocida","historyNoCapture":"No hay ninguna captura cargada. Los registros existentes permanecen intactos.","historyInventorySummary":"Captura: {count} elementos, {size}. Creada: {at}.","historyPageSummary":"Se muestran {count} elementos de esta captura.","historyEmpty":"Esta captura no contiene elementos.","historyDetailTitle":"Registro: {record}","historyDetailLoading":"Cargando el registro seleccionado exacto…","historyRawUnavailable":"Este elemento no puede leerse de forma segura como un registro normal de tamaño limitado. Sus pruebas permanecen intactas.","historyDetailUnavailable":"La vista estructurada no está disponible. Descarga el registro original para examinarlo de forma privada.","historyCapturing":"Capturando metadatos privados… No se eliminarán las pruebas existentes.","historyLoading":"Cargando el historial capturado…","historyCaptureNeeded":"El historial necesita una captura nueva. Selecciona Capturar historial; los registros permanecerán intactos.","historyRecordUnavailable":"El registro seleccionado no está disponible. Captura el historial de nuevo para revisar su estado actual.","historyRequestEnded":"La solicitud terminó antes de completarse. Inténtalo de nuevo; no se eliminó ningún registro.","historyCapacity":"El historial supera los límites de inspección. Se conservan todos los registros y las pruebas de recuperación.","historyBusy":"El historial está ocupado. Inténtalo de nuevo en breve; ninguna operación se repetirá automáticamente.","historyInvalidResponse":"No se pudo verificar la respuesta del historial. No se creó ninguna descarga.","historyFailed":"No se pudo leer el historial. Los registros y las pruebas de recuperación permanecen intactos.","historyClass_canonical":"Registro reconocido","historyClass_legacy":"Registro anterior","historyClass_malformed":"Registro JSON no válido","historyClass_oversized":"Supera el límite de inspección","historyClass_special":"Tipo de archivo no admitido","historyClass_unreadable":"Registro ilegible","historyState_running":"En ejecución","historyState_succeeded":"Completado","historyState_failed":"Fallido","historyState_interrupted":"Interrumpido","historyState_unknown":"Desconocido","historyCancelCapture":"Cancelar solicitud de captura","historyCaptureCanceled":"Solicitud de captura cancelada. Los registros y las pruebas de recuperación no han cambiado. Recarga la captura para comprobar los metadatos completados."});

Object.assign(extraLocales.ru,{"lifecycleTitle":"Контроль завершения","lifecycleRefresh":"Обновить состояние завершения","lifecycleNotice":"Учитывается только закрытие локального процесса и записи. Изменения сторонних программ и право удаления данных восстановления не подтверждаются.","lifecycleNotLoaded":"Состояние завершения ещё не прочитано. Данные не изменены.","lifecycleLoading":"Чтение локальных данных завершения…","lifecycleState_none":"Локальная квитанция завершения не отслеживается. Старые данные защищены; это не разрешение запуска и не проверка свободного места.","lifecycleState_intent":"Локальное намерение операции не завершено. Сохраните ввод и данные восстановления.","lifecycleState_sealed":"Локальный результат запечатан, но освобождение владельцев не подтверждено. Сохраните данные восстановления.","lifecycleState_released":"Закрытие локального процесса, записи и исходной блокировки наблюдалось. Очистка сторонних программ и удаление данных не подтверждаются.","lifecycleState_blocked":"Локальные данные завершения требуют проверки. Новые операции заблокированы.","lifecycleAdmissionBlocked":"Новые операции заблокированы из-за неподтверждённого локального завершения. Сохраните ввод и данные восстановления; просмотр истории и отмена текущей операции доступны. Автоматического повтора нет.","lifecycleGeneration":"Отслеживаемая операция","lifecycleBusy":"Состояние завершения занято или недоступно. Повторите чтение; операции не повторялись.","lifecycleEnded":"Запрос состояния завершения окончен. Данные не изменены.","lifecycleUnavailable":"Состояние завершения не удалось проверить. Успешное закрытие не предполагается."});
Object.assign(extraLocales.es,{"lifecycleTitle":"Seguimiento de finalización","lifecycleRefresh":"Actualizar estado de finalización","lifecycleNotice":"Solo registra el cierre del trabajador y del registro local. No certifica cambios de proveedores ni permite eliminar pruebas de recuperación.","lifecycleNotLoaded":"No se ha leído el estado de finalización. Las pruebas no han cambiado.","lifecycleLoading":"Leyendo pruebas de finalización local…","lifecycleState_none":"No se registra ningún recibo local de finalización. Las pruebas anteriores siguen protegidas; esto no autoriza un inicio ni garantiza capacidad de almacenamiento.","lifecycleState_intent":"La intención de una operación local sigue pendiente. Conserva las entradas y las pruebas de recuperación.","lifecycleState_sealed":"El resultado local está sellado, pero no se confirmó la liberación de sus propietarios. Conserva las pruebas de recuperación.","lifecycleState_released":"Se observó el cierre del trabajador, el registro y el bloqueo original locales. No se certifican la limpieza de proveedores ni la retirada de pruebas.","lifecycleState_blocked":"Las pruebas locales de finalización requieren revisión. Se bloquean nuevas operaciones.","lifecycleAdmissionBlocked":"Las pruebas locales de finalización pendientes bloquean nuevas operaciones. Conserva las entradas y las pruebas; la consulta del historial y la cancelación de la operación actual siguen disponibles. No se repite nada automáticamente.","lifecycleGeneration":"Operación registrada","lifecycleBusy":"El estado de finalización está ocupado o no disponible. Repite la lectura; no se repitió ninguna operación.","lifecycleEnded":"La solicitud del estado de finalización terminó. Las pruebas no han cambiado.","lifecycleUnavailable":"No se pudo verificar el estado de finalización. No se presupone un cierre correcto."});

Object.assign(extraLocales.ru,{"probeCancel":"Отменить тест","probeCanceled":"Запрошена отмена. Введённые данные сохранены. Незавершённые результаты отброшены; автоматического повтора нет.","probeInputsCleared":"Ввод изменён. Предыдущие результаты диагностики очищены. Запустите тест явно.","probeContextCleared":"Изменилось соединение, сеанс или режим приложения. Предыдущие результаты диагностики очищены. Ввод сохранён.","probeViewCleared":"Раздел диагностики закрыт. Ввод сохранён, предыдущие результаты очищены. Автоматического повтора нет.","probeBusy":"Другая диагностика выполняется или ещё завершается. Ввод сохранён. Подождите и запустите тест явно; автоматического повтора нет.","probeRequestEnded":"Запрос диагностики завершился до получения результата. Ввод сохранён. Запустите новый тест явно."});
Object.assign(extraLocales.es,{"probeCancel":"Cancelar prueba","probeCanceled":"Cancelación solicitada. Se conservan las entradas. Se descartan los resultados incompletos; no se repite ninguna prueba automáticamente.","probeInputsCleared":"Las entradas cambiaron. Se borraron los resultados de diagnóstico anteriores. Inicia una prueba explícitamente.","probeContextCleared":"La conexión, la sesión o el modo de la aplicación cambió. Se borraron los resultados de diagnóstico anteriores. Se conservan las entradas.","probeViewCleared":"Se cerró la vista de diagnóstico. Se conservan las entradas y se borraron los resultados anteriores. No se repite ninguna prueba automáticamente.","probeBusy":"Otro diagnóstico está activo o aún termina. Se conservan las entradas. Espera e inicia una prueba explícitamente; no se reintenta nada automáticamente.","probeRequestEnded":"La solicitud de diagnóstico terminó antes de completarse. Se conservan las entradas. Inicia otra prueba explícitamente."});

Object.assign(extraLocales.ru,{"reconcileTitle":"Проверка локального закрытия","reconcileRefresh":"Обновить состояние согласования","reconcileNotice":"Перед записью освобождения проверьте положительные доказательства локального владения. Это не подтверждает очистку сторонних программ и не разрешает удалять записи.","reconcileGenerationInput":"Идентификатор операции (необязательно: текущая)","reconcileOperationInput":"Известный идентификатор согласования","reconcileInputNote":"Используйте идентификаторы из приложения. Нельзя считать неизвестных или аварийно завершённых владельцев освобождёнными. Просмотр и отмена текущей задачи доступны.","reconcileReviewCurrent":"Проверить локальное освобождение","reconcileReviewResume":"Проверить возобновление","reconcileReadReceipt":"Прочитать квитанцию операции","reconcileStopReceipt":"Остановить проверку квитанции","reconcileReviewTitle":"Проверка перед применением","reconcileReviewNotice":"Согласуется только проверенное локальное освобождение. Исходные ошибки задачи и данные восстановления сохраняются.","reconcileConsent":"Я проверил локальное освобождение, идентификаторы и сохраняемые метаданные. Применить один раз.","reconcileApply":"Применить проверенное согласование","reconcileReceiptTitle":"Завершённая локальная квитанция","reconcileReceiptNotice":"Подтверждается только освобождение исходных локальных владельцев. Исходный результат задачи не меняется; состояние сторонних программ и удаление не подтверждены.","reconcileObjects":"Закрытые этапы метаданных для сохранения","reconcilePreservedObjects":"Этапы метаданных, сохранённые операцией","reconcileObjectRef":"Ссылка на объект","reconcileDigest":"Отпечаток","reconcileGeneration":"Идентификатор задачи","reconcileOperation":"Идентификатор согласования","reconcileExpires":"Срок действия проверки","reconcileRevision":"Отпечаток проверки","reconcileCompletedAt":"Локальное завершение записано","reconcileRole":"Закрытые метаданные подтверждения","reconcileNotLoaded":"Проверка согласования не загружена. Данные не изменены.","reconcileReadingStatus":"Чтение состояния локального согласования…","reconcileReviewing":"Чтение точных локальных данных для проверки… Освобождение ещё не применяется.","reconcileReviewReady":"Проверьте точные идентификаторы и сохраняемые метаданные, затем отдельно подтвердите однократное применение.","reconcileApplying":"Однократное применение проверенного локального согласования. Уход прекращает ожидание браузера, но не зафиксированную операцию; сохраните идентификатор.","reconcileReadingReceipt":"Чтение точной квитанции операции…","reconcileReceiptPending":"Завершённой квитанции пока нет. Идентификатор проверяется только для чтения; остановка проверки не отменяет операцию.","reconcileStillPending":"Завершённая квитанция не обнаружена. Сохраните идентификатор и данные. Прочитайте снова или явно проверьте возобновление; применение не повторяется автоматически.","reconcileReceiptNeeded":"Сохраните идентификатор согласования. Прочитайте квитанцию для проверки локального результата. Незавершённая работа требует новой явной проверки возобновления; применение не повторяется автоматически.","reconcileWatchStopped":"Проверка квитанции остановлена. Идентификатор и данные сохранены; операции не отменялись и не повторялись.","reconcileCompleted":"Проверенное локальное закрытие записано. Исходные результаты и данные сохранены; это не подтверждение очистки сторонних программ или удаления.","reconcileState_none":"Текущая операция согласования не отслеживается. Старые данные защищены.","reconcileState_available":"Доступно положительное локальное доказательство для явной проверки. Это не автоматическое освобождение и не разрешение запуска.","reconcileState_pending":"Намерение согласования не завершено. Прочитайте известную квитанцию; для возобновления всегда нужна новая проверка.","reconcileState_completed":"Для просмотра доступна завершённая локальная квитанция. Она не меняет исходный результат задачи.","reconcileState_unavailable":"Положительное доказательство локального владения недоступно. Сохраните исходные данные.","reconcileInvalidResponse":"Ответ согласования не удалось проверить. Освобождение не предполагается.","reconcileInvalid":"Используйте корректные идентификаторы и проверьте операцию снова.","reconcileUnavailable":"Положительное доказательство локального владения недоступно. Новый сеанс не может считать ресурсы аварийных владельцев освобождёнными; сохраните данные.","reconcileConflict":"Локальные данные изменились. Проверьте снова; запрос применения не повторяется.","reconcileExpired":"Срок проверки истёк. Подтверждение снято; перед применением проверьте снова.","reconcilePending":"Операция не завершена. Сохраните идентификатор и прочитайте квитанцию до проверки возобновления.","reconcileDenied":"Политика администратора не разрешает согласование жизненного цикла. Другие разрешения профиля его не предоставляют.","reconcilePolicyUnavailable":"Политику администратора не удалось проверить. Согласование недоступно.","reconcileEnded":"Запрос браузера завершился до подтверждённого ответа. Сохраните известные идентификаторы и проверьте квитанции.","reconcileBusy":"Локальное согласование занято. Явно повторите чтение или проверку позже; изменения не ставятся в очередь и не повторяются.","reconcileStoreUnavailable":"Локальное хранилище согласования не удалось проверить. Сохраните данные и известные идентификаторы."});
Object.assign(extraLocales.es,{"reconcileTitle":"Revisar cierre local","reconcileRefresh":"Actualizar estado de conciliación","reconcileNotice":"Revisa las pruebas positivas de propiedad local antes de registrar la liberación. No certifica limpieza de proveedores ni permite borrar o retirar registros.","reconcileGenerationInput":"Identificador de tarea (opcional: actual)","reconcileOperationInput":"Identificador de conciliación conocido","reconcileInputNote":"Usa identificadores devueltos por la aplicación. No se presupone la liberación de propietarios desconocidos o interrumpidos. La consulta y la cancelación de la tarea actual siguen disponibles.","reconcileReviewCurrent":"Revisar liberación local","reconcileReviewResume":"Revisar reanudación","reconcileReadReceipt":"Leer recibo de la operación","reconcileStopReceipt":"Dejar de consultar el recibo","reconcileReviewTitle":"Revisar antes de aplicar","reconcileReviewNotice":"Solo se concilia la liberación local revisada. Se conservan los fallos originales y las pruebas de recuperación.","reconcileConsent":"He revisado esta liberación local, sus identificadores y los metadatos conservados. Aplicar una vez.","reconcileApply":"Aplicar conciliación revisada","reconcileReceiptTitle":"Recibo local completado","reconcileReceiptNotice":"Solo confirma la liberación de los propietarios locales originales. El resultado original no cambia; el estado del proveedor y la retirada siguen sin verificarse.","reconcileObjects":"Etapas cerradas de metadatos que se conservarán","reconcilePreservedObjects":"Etapas de metadatos conservadas por la operación","reconcileObjectRef":"Referencia del objeto","reconcileDigest":"Huella","reconcileGeneration":"Identificador de tarea","reconcileOperation":"Identificador de conciliación","reconcileExpires":"Caducidad de la revisión","reconcileRevision":"Huella de la revisión","reconcileCompletedAt":"Finalización local registrada","reconcileRole":"Metadatos cerrados de confirmación","reconcileNotLoaded":"No hay ninguna revisión de conciliación cargada. Las pruebas no han cambiado.","reconcileReadingStatus":"Leyendo el estado de conciliación local…","reconcileReviewing":"Leyendo las pruebas locales exactas para revisión… Aún no se aplica ninguna liberación.","reconcileReviewReady":"Revisa los identificadores exactos y los metadatos conservados; después confirma por separado la aplicación una sola vez.","reconcileApplying":"Aplicando una vez esta conciliación local revisada. Salir detiene la espera del navegador, no una operación confirmada; conserva su identificador.","reconcileReadingReceipt":"Leyendo el recibo exacto de la operación…","reconcileReceiptPending":"Aún no hay un recibo completado. Se consulta este identificador en modo de lectura; detener la consulta no deshace la operación.","reconcileStillPending":"No se observó un recibo completado. Conserva el identificador y las pruebas. Lee de nuevo o revisa explícitamente la reanudación; Aplicar nunca se repite automáticamente.","reconcileReceiptNeeded":"Conserva el identificador de conciliación. Lee el recibo para confirmar el resultado local. El trabajo pendiente requiere una revisión explícita nueva para reanudarse; Aplicar nunca se repite automáticamente.","reconcileWatchStopped":"Se detuvieron las consultas del recibo. Se conservan el identificador y las pruebas; no se deshizo ni repitió ninguna operación.","reconcileCompleted":"Se registró el cierre local revisado. Se conservan los resultados originales y las pruebas; esto no aprueba limpieza de proveedores ni retirada.","reconcileState_none":"No se registra ninguna conciliación actual. Las pruebas anteriores siguen protegidas.","reconcileState_available":"Hay pruebas locales positivas para revisión explícita. No es una liberación automática ni una autorización de inicio.","reconcileState_pending":"Hay una intención de conciliación pendiente. Lee su recibo conocido; reanudar siempre requiere una revisión nueva.","reconcileState_completed":"Hay un recibo local completado para consultar. No cambia el resultado original de la tarea.","reconcileState_unavailable":"No hay pruebas positivas de propiedad local. Conserva las pruebas originales.","reconcileInvalidResponse":"No se pudo verificar la respuesta de conciliación. No se presupone ninguna liberación.","reconcileInvalid":"Usa identificadores válidos y revisa de nuevo la operación.","reconcileUnavailable":"No hay pruebas positivas de propiedad local. Una sesión nueva no puede suponer que los propietarios interrumpidos liberaron sus recursos; conserva las pruebas.","reconcileConflict":"Las pruebas locales cambiaron. Revísalas de nuevo; no se repite ninguna solicitud de Aplicar.","reconcileExpired":"La revisión caducó. Se borró el consentimiento; revisa de nuevo antes de aplicar.","reconcilePending":"La operación está incompleta. Conserva su identificador y lee el recibo antes de revisar cualquier reanudación.","reconcileDenied":"La política del administrador no permite conciliar el ciclo de vida. Otros permisos de perfil no lo autorizan.","reconcilePolicyUnavailable":"No se pudo verificar la política del administrador. La conciliación sigue sin estar disponible.","reconcileEnded":"La solicitud del navegador terminó antes de una respuesta confirmada. Conserva los identificadores conocidos y consulta los recibos.","reconcileBusy":"La conciliación local está ocupada. Intenta explícitamente la lectura o revisión más tarde; no se encola ni repite ninguna modificación.","reconcileStoreUnavailable":"No se pudo verificar el almacenamiento de conciliación local. Conserva las pruebas y los identificadores conocidos."});

Object.assign(extraLocales.ru,{reconcileIntentDigest:'SHA-256 намерения',reconcileSealDigest:'SHA-256 завершения',reconcileAckDigest:'SHA-256 подтверждения освобождения'});
Object.assign(extraLocales.es,{reconcileIntentDigest:'SHA-256 de intención',reconcileSealDigest:'SHA-256 del cierre',reconcileAckDigest:'SHA-256 de confirmación de liberación'});
