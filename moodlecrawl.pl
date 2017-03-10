use strict;
use warnings;
use LWP::UserAgent;
use Getopt::Long;
use Digest::SHA;
 
$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;

my %opciones;

GetOptions (\%opciones, 'help|h', 'ip|s=s', 'dic|d=s', 'login|l=s', 'pass|p=s',
	    'report|r=s'
);

if ($opciones{help}){
    muestraAyuda();
    exit (1);
}

my $ua = LWP::UserAgent->new();

my $uaSSL = LWP::UserAgent->new(
    ssl_opts => { SSL_verify_mode => 'SSL_VERIFY_NONE' },
    SSL_ca_path => "/etc/ssl/certs/",
);

# Datos de prueba
$ua->agent('Mozilla/5.0');
my $url = 'http://192.168.13.149/';
#my $url = 'https://aula.cert.unam.mx/';
my $req = HTTP::Request->new(GET => $url);
#my $reqSSL = HTTP::Request->new(GET => $url);
#my $req = HTTP::Request->new(GET => 'http://bpya.fciencias.unam.mx/moodle/');
#my $res = $uaSSL->request($reqSSL);
my $res = $ua->request($req);

my $archivoSalida="moodleCrawlOUT.html";

my $tipoSalida = "html";

encabezadoHTML($archivoSalida);

#print "Codigo de respuesta: ".$res->code."\n\n";

($tipoSalida eq 'html')? agregaArchivo($archivoSalida, "<p>Codigo de respuesta: ".$res->code."</p>\n") : agregaArchivo($archivoSalida, "Codigo de respuesta: ".$res->code."\n\n");

if ($res->is_success) { 
    # Revisamos los encabezados, pasamos el resultado HTTP, el nombre del archivo de salida y el formato de esta
    analizaEncabezado($res, $archivoSalida, $tipoSalida);
}
else {
    ($tipoSalida eq 'html')? agregaArchivo($archivoSalida, "<p>Failed: ".$res->status_line."</p>\n") : agregaArchivo($archivoSalida, "Failed: ", $res->status_line, "\n");
}

pieHTML($archivoSalida);

exit (0);

# Revisamos la respuesta a los errores 403, 404 y 500
analizaCodigosError($url, $archivoSalida, $tipoSalida);

my $dic = "dicMoodle2";

# Hacemos la revisión de los directorios contenidos en el diccionario
revisaDiccionario($url, $dic);


sub analizaCodigosError{
    my ($url, $fileOut, $tipoSalida) = @_; # Recibimos la URL, el nombre del archivo de salida y el tipo de salida a generar

    # Intentamos abrir el archivo de salida para agregar informacion
    open(SALIDA, ">>", $fileOut)
	or die "No se puede abrir el archivo para agregar la salida.";

    my ($ua, $res403, $res404, $res500, $req);

    # Error 403
    print "Analisis de error 403:\n";
    $ua = LWP::UserAgent->new();
    $ua->agent('Mozilla/5.0');
    $req = HTTP::Request->new(GET => $url.'archivoParaError403.php');
    $res403 = $ua->request($req);
    print "\tURL para generar error 403: ".$url."archivoParaError403.php\n";
    print "\tCodigo de respuesta: ".$res403->code."\n";
    if (grep(/Apache\/.*[0-9]+\.[0-9]+/, $res403->content))
    {
	print "\tDiagnostico: el servidor revela informacion que deberia mantenerse como privada.\n";
	print "\tRecomendacion: incluir 'ServerTokens Prod' y 'ServerSignature' en la configuracion de Apache para reducir la informacion divulgada.\n";
	print "\tTambien se dede definir la respuesta para el error 404 en el servidor Web\n\n";
    }
    else
    {
	print "\tDiagnostico: el servidor no revela informacion privada.\n\n";
    }

    # Error 404
    print "Analisis de error 404:\n";
    $ua = LWP::UserAgent->new();
    $ua->agent('Mozilla/5.0');
    $req = HTTP::Request->new(GET => $url.'archivoParaError404.php');
    $res404 = $ua->request($req);
    print "\tURL para generar error 404: ".$url."archivoParaError404.php\n";
    print "\tCodigo de respuesta: ".$res404->code."\n";
    if (grep(/Apache\/.*[0-9]+\.[0-9]+/, $res404->content))
    {
	print "\tDiagnostico: el servidor revela informacion que deberia mantenerse como privada.\n";
	print "\tRecomendacion: incluir 'ServerTokens Prod' y 'ServerSignature' en la configuracion de Apache para reducir la informacion divulgada.\n";
	print "\tTambien se dede definir la respuesta para el error 404 en el servidor Web\n\n";
    }
    else
    {
	print "\tDiagnostico: el servidor no revela informacion privada.\n\n";
    }

    # Error 500
    print "Analisis de error 500:\n";
    $req = HTTP::Request->new(GET => $url.'version.php');
    $res500 = $ua->request($req);
    print "\tURL y metodo para generar error 500: GET ".$url."version.php\n";
    print "\tCodigo de respuesta: ".$res500->code."\n";
    if (grep(/Apache\/.*[0-9]+\.[0-9]+/, $res500->content))
    {
	print "\tDiagnostico: el servidor revela informacion que deberia mantenerse como privada.\n";
	print "\tRecomendacion: incluir 'ServerTokens Prod' y 'ServerSignature' en la configuracion de Apache para reducir la informacion divulgada.\n";
	print "\tTambien se dede definir la respuesta para el error 500 en el servidor Web\n\n";
    }
    else
    {
	print "\tDiagnostico: el servidor no revela informacion privada.\n\n";
    }
}



#
# Hace una revision de los directorios del archivo que contiene el diccionario en el servidor analizado, 
# en caso de que el usuario lo indique.
#
sub revisaDiccionario{ 
    my ($url, $dicFile) = @_; # Recibimos la url a analizar y el nombre del diccionario
    my ($ua, $res, $req, $urlDir);

    print "Analisis de diccionario:\n";
    $ua = LWP::UserAgent->new();
    $ua->agent('Mozilla/5.0');

    # Intentamos abrir el diccionario
    open (DIRECTORIOS, $dicFile)
	or die "No se puede abrir el archivo de contrasenias\n";

    # Intentamos cada uno de los directorios en el servidor y revisamos los codigos 
    # devueltos para la peticion HTTP
    while (<DIRECTORIOS>) {
	chomp($_);
	$urlDir = $url.$_;
	$req = HTTP::Request->new(GET => $urlDir);
	$res = $ua->request($req);
	print "$urlDir\n";
	print "\tDiagnostico: ";
	if ($res->code == 200){
	    print "El directorio existe y es accesible.\n\n";
	}
	else{
	    if ($res->code == 403){
		print "El directorio existe pero se requieren privilegios para acceder.\n\n";
	    }
	    else{
		if ($res->code == 404){
		    print "El directorio no existe.\n\n";
		}
		else{
		    if ($res->code >= 300 && $res->code < 400){
			print "La peticion fue redirigida.\n\n";
		    }
		    else{
			print "El servidor reporto el error ".$res->code."\n\n";
		    }
		}
	    }
	}
    }
    close (DIRECTORIOS);
}


#
# Revisa algunas de las principales cabeceras de la respuesta de HTTP, muestra un 
# diagnostico y, en caso necesario, una recomendacion de seguridad.
#
sub analizaEncabezado{
    my ($resp, $fileOut, $tipoSalida) = @_; # Recibimos la respuesta HTTP, el nombre del archivo de salida y el tipo de salida a generar

    # Intentamos abrir el archivo de salida para agregar informacion
    open(SALIDA, ">>", $fileOut)
	or die "No se puede abrir el archivo para agregar la salida.";

    ($tipoSalida eq 'html')? print SALIDA "<p>Analisis de encabezados:</p>\n" : print SALIDA "Analisis de encabezados:\n\n";

    # Revisamos la cabecera Server
    ($tipoSalida eq 'html')? print SALIDA "<p>Cabecera Server: </p>\n<table border=1>\n" : print SALIDA "Cabecera Server:\n";
    if ($res->header('Server'))
    {
	($tipoSalida eq 'html')? print SALIDA "<tr><td class='celdaNom'>Valor devuelto</td><td class='celdaTexto'>".$res->header('Server')."</td></tr>\n" : print SALIDA "\tValor devuelto: ".$res->header('Server')."\n";
    }
    ($tipoSalida eq 'html')? print SALIDA "<tr><td class='celdaNom'>Diagnostico</td>" : print SALIDA "\tDiagnostico: ";
    if ($res->header('Server') =~ /^Apache.*[0-9]+[a-zA-Z]*/){
	($tipoSalida eq 'html')? print SALIDA "<td class='celdaTexto'>Server Tokens mal configurados</td></tr>\n" : print SALIDA "Server Tokens mal configurados\n";
	($tipoSalida eq 'html')? print SALIDA "<tr><td class='celdaNom'>Recomendacion</td><td class='celdaTexto'>Incluir 'ServerTokens Prod' y 'ServerSignature' en la configuracion de Apache para reducir la informacion divulgada.</td></tr></table>\n": print SALIDA "\tRecomendacion: incluir 'ServerTokens Prod' y 'ServerSignature' en la configuracion de Apache para reducir la informacion divulgada.\n\n";
    }
    else {
	($tipoSalida eq 'html')? print SALIDA "<tr><td class='celdaNom'>ServerTokens configurados.</td></tr></table>\n" : print SALIDA "ServerTokens configurados.\n\n";
    }

    # Revisamos X-Powered-By
    ($tipoSalida eq 'html')? print SALIDA "<p>Cabecera X-Powered-By: </p>\n<table border=1>\n" : print SALIDA "Cabecera X-Powered-By:\n";
    if ($res->header('X-Powered-By'))
    {
	($tipoSalida eq 'html')? print SALIDA "<tr><td class='celdaNom'>Valor devuelto</td><td class='celdaTexto'>".$res->header('X-Powered-By')."</td></tr>\n" : print SALIDA "\tValor devuelto: ".$res->header('X-Powered-By')."\n";
	($tipoSalida eq 'html')? print SALIDA "<tr><td class='celdaNom'>Diagnostico</td><td class='celdaTexto'>X-Powered-By habilitada</td>" : print SALIDA "\tDiagnostico: X-Powered-By habilitada";
	($tipoSalida eq 'html')? print SALIDA "<tr><td class='celdaNom'>Recomendacion</td><td class='celdaTexto'>Deshabilitar esta opcion para reducir la informacion divulgada del servidor</td></tr></table>\n" : print SALIDA "\tRecomendacion: deshabilitar esta opcion para reducir la informacion divulgada del servidor.\n\n";
    }
    else
    {
	($tipoSalida eq 'html')? print SALIDA "<tr><td class='celdaNom'>Diagnostico</td><td class='celdaTexto'>Cabecera X-Powered-By deshabilitada</td></tr></table>\n" : print SALIDA "\tDiagnostico: Cabecera X-Powered-By deshabilitada.\n\n";
    }

    # Revisamos X-XSS-Protection
    ($tipoSalida eq 'html')? print SALIDA "<p>Cabecera X-XSS-Protection: </p>\n<table border=1>\n" : print SALIDA "Cabecera X-XSS-Protection:\n";
    if ($res->header('X-XSS-Protection'))
    {
	($tipoSalida eq 'html')? print SALIDA "<tr><td class='celdaNom'>Valor devuelto</td><td class='celdaTexto'>".$res->header('X-XSS-Protection')."</td></tr>\n" : print SALIDA "\tValor devuelto: ".$res->header('X-XSS-Protection')."\n\n";
	($tipoSalida eq 'html')? print SALIDA "<tr><td class='celdaNom'>Diagnostico</td><td class='celdaTexto'>X-XSS-Protection habilitada</td></tr></table>" : print SALIDA "\tDiagnostico: X-XSS-Protection habilitada.\n\n";
    }
    else
    {
	($tipoSalida eq 'html')? print SALIDA "<tr><td class='celdaNom'>Diagnostico</td><td class='celdaTexto'>X-XSS-Protection no esta habilitada</td></tr>" : print SALIDA "\tDiagnostico: X-XSS-Protection no esta habilitada.\n";
	($tipoSalida eq 'html')? print SALIDA "<tr><td class='celdaNom'>Recomendacion</td><td class='celdaTexto'>Habilitar el encabezado 'X-XSS-Protection: 1;mode=block' para reducir el riesgo de ataques de tipo XSS</td></tr></table>\n" : print "\tRecomendacion: habilitar el encabezado 'X-XSS-Protection: 1;mode=block' para reducir el riesgo de ataques de tipo XSS.\n\n";
    }

    # Revisamos X-Frame-Options
    ($tipoSalida eq 'html')? print SALIDA "<p>Cabecera X-Frame-Options: </p>\n<table border=1>\n" : print SALIDA "Cabecera X-Frame-Options:\n";
    if ($res->header('X-Frame-Options'))
    {
	($tipoSalida eq 'html')? print SALIDA "<tr><td class='celdaNom'>Valor devuelto</td><td class='celdaTexto'>".$res->header('X-Frame-Options')."</td></tr>\n" : print SALIDA "\tValor devuelto: ".$res->header('X-Frame-Options')."\n";
	($tipoSalida eq 'html')? print SALIDA "<tr><td class='celdaNom'>Diagnostico</td><td class='celdaTexto'>X-Frame-Options esta habilitada</td></tr></table>\n" : print SALIDA "\tDiagnostico: X-Frame-Options esta habilitada.\n\n";
    }
    else
    {
	($tipoSalida eq 'html')? print SALIDA "<tr><td class='celdaNom'>Diagnostico</td><td class='celdaTexto'>X-Frame-Options no esta habilitada</td></tr>" : print SALIDA "\tDiagnostico: X-Frame-Options no esta habilitada.\n";
	($tipoSalida eq 'html')? print SALIDA "<tr><td class='celdaNom'>Recomendacion</td><td class='celdaTexto'>Habilitar 'X-Frame-Options: SAMEORIGIN' para reducir el riesgo de ataques de tipo clickjacking</td></tr></table>\n" : print SALIDA "\tRecomendacion: habilitar 'X-Frame-Options: SAMEORIGIN' para reducir el riesgo de ataques de tipo clickjacking.\n\n";	
    }

    # Mostramos los datos del servidor
    if ($res->header('Client-Peer'))
    {
	($tipoSalida eq 'html')? print SALIDA "<p>Datos del servidor: </p>\n<table border=1>\n" : print SALIDA "Datos del servidor:\n";
	my @urlPart = split(/:/,$res->header('Client-Peer'));
	($tipoSalida eq 'html')? print SALIDA "<tr><td class='celdaNom'>Direccion</td><td class='celdaTexto'>".$urlPart[0]."</td></tr>" : print SALIDA "\tDireccion: ".$urlPart[0]."\n";
	($tipoSalida eq 'html')? print SALIDA "<tr><td class='celdaNom'>Puerto</td><td class='celdaTexto'>".$urlPart[1]."</td></tr></table>\n" : print SALIDA "\tPuerto: ".$urlPart[1]."\n";
    }

    # Revisamos Accept-Ranges para verificar si el servidor acepta peticiones parciales
    ($tipoSalida eq 'html')? print SALIDA "<p>Cabecera Accept-Ranges: </p>\n<table border=1>\n" : print SALIDA "Cabecera Accept-Ranges:\n";
    if ($res->header('Accept-Ranges') ne 'none')
    {
	($tipoSalida eq 'html')? print SALIDA "<tr><td class='celdaNom'>Diagnostico</td><td class='celdaTexto'>Accept-Ranges habilitada, el servidor puede aceptar peticiones parciales</td></tr></table>\n" : print SALIDA "\tDiagnostico: Accept-Ranges habilitada, el servidor puede aceptar peticiones parciales.\n\n";
    }
    else
    {
	($tipoSalida eq 'html')? print SALIDA "<tr><td class='celdaNom'>Diagnostico</td><td class='celdaTexto'>Accept-Ranges deshabilitada, el servidor no acepta peticiones parciales</td></tr></table>\n" : print "\tDiagnostico: Accept-Ranges deshabilitada, el servidor no acepta peticiones parciales.\n\n";
    }
    close (SALIDA);
}


#
# Recibe un nombre de archivo y coloca un encabezado HTML siguiendo los estandares de la W3C.
#
sub encabezadoHTML{
    my $file = shift @_; # Recibe el nombre del archivo en el que se colocara el HTML

    # Intentamos abrir el archivo de salida
    open(SALIDA, ">", $file)
	or die "No se puede abrir el archivo para la salida HTML.";

    # Agregamos el encabezado HTML
    print SALIDA "<!DOCTYPE html PUBLIC '-//W3C//DTD XHTML 1.0 Transitional//EN' 'http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd'>\n";
    print SALIDA "<html xmlns='http://www.w3.org/1999/xhtml'>\n";
    print SALIDA "<head>\n";
    print SALIDA "<meta content='text/html; charset=UTF-8' http-equiv='content-type'/>\n";
    print SALIDA "<title>Coordinación de Cómputo</title>\n";
    print SALIDA "<style>\n";
    print SALIDA ".celdaNom{ width: 150px;}\n";
    print SALIDA ".celdaTexto{ width: 900px;}\n";
    print SALIDA "table { border: 1px solid; border-collapse: collapse; }\n";
    print SALIDA "td { padding: 5px;}\n";
    print SALIDA "</style>\n";
    print SALIDA "</head>\n";
    print SALIDA "<body>\n";
    close (SALIDA);
}


#
# Agrega una entrada al archivo indicado.
# En caso de que el archivo de salida tenga formato HTML, la cadena recibida ya debe
# estar formateada.
#
sub agregaArchivo{
    my ($file, $texto) = @_; # Recibe el nombre del archivo y la cadena a agregar

    # Intentamos abrir el archivo de salida para agregar
    open(SALIDA, ">>", $file)
	or die "No se puede abrir el archivo para agregar la salida.";

    # Agregamos el texto con una linea en blanco
    print SALIDA $texto."\n\n";
    close (SALIDA);
}


#
# Recibe un nombre de archivo y coloca al final las etiquetas de cierre de HTML
#
sub pieHTML{
    my $file = shift @_; # Recibe el nombre del archivo en el que se colocara el HTML

    # Intentamos abrir el archivo de salida para agregar las etiquetas de cierre
    open(SALIDA, ">>", $file)
	or die "No se puede abrir el archivo para la salida HTML.";

    # Agregamos las etiquetas y cerramos el archivo
    print SALIDA "</body>\n";
    print SALIDA "</html>\n";
    close (SALIDA);
}


##
## muestraAyuda muestra al usuario como se debe usar este programa.
##
sub muestraAyuda {
    print "$0 implementa un 'web crawling' para sitios basados en Moodle, lleva a cabo un analisis del sitio indicado revisando la informacion divulgada.\n\n";
    print "Forma de uso:\n";
    print "  $0 [--help|-h] [[--ip|-s] <direccion ip>] [[--dic|-d] <diccionario>] \n";
    print ' 'x (length($0)+3), "[[--login|-l] <usuario>] [[--pass|-p] <password>] [[--report|-r] [text|html]] URL\n\n";
    print "Donde:\n";
    print "--help o -h\t Muestra esta ayuda\n";
    print "--ip o -s\t Indica la direccion IP del equipo a analizar\n";
    print "--dic o -d\t Indica el nombre del archivo que contiene el diccionario de directorios a revisar en el equipo a analizar\n";
    print "--login o -l\t Indica el nombre de usuario a usar para conectarse al equipo analizado\n";
    print "--pass o -p\t Indica el password a utilizar para conectarse al equipo analizado\n";
    print "--report o -r\t Indica como se debe generar el reporte. Las opciones son 'text' y 'html', siendo la primera la opcion predeterminada.\n\n";
    print "Las opciones --ip y -s son excluyentes con la URL. En caso de incluirse una de las opciones y la URL, esta ultima se ignorara y se hara uso de la expresion incluida en las opciones mencionadas.\n";
    print "Todos los parametros son opcionales.\n";
}



#http://search.cpan.org/~ether/HTTP-Message-6.11/lib/HTTP/Response.pm
#http://search.cpan.org/~oalders/libwww-perl-6.23/lib/LWP/UserAgent.pm
#http://stackoverflow.com/questions/4022463/how-can-i-extract-non-standard-http-headers-using-perls-lwp
#http://search.cpan.org/~ether/HTTP-Message-6.11/lib/HTTP/Headers.pm
#http://search.cpan.org/~ether/HTTP-Message-6.11/lib/HTTP/Message.pm
###
#http://lwp.interglacial.com/ch03_05.htm

