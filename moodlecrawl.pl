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
$ua->agent('Mozilla/5.0');
#my $url = 'http://192.168.13.149/';
my $url = 'https://aula.cert.unam.mx/';
#my $req = HTTP::Request->new(GET => $url);
my $reqSSL = HTTP::Request->new(GET => $url);
#my $req = HTTP::Request->new(GET => 'http://bpya.fciencias.unam.mx/moodle/');
my $res = $uaSSL->request($reqSSL);
#my $res = $ua->request($req);

print "Codigo de respuesta: ".$res->code."\n\n";

if ($res->is_success) { 
    analizaEncabezado($res);
}
else {
    print "Failed: ", $res->status_line, "\n";
}
analizaCodigosError($url);

my $dic = "dicMoodle2";

revisaDiccionario($url, $dic);

sub analizaCodigosError{
    my $url = shift @_;
    my ($ua, $res403, $res404, $res500, $req);

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

    print "Analisis de error 403:\n";
    $ua = LWP::UserAgent->new();
    $ua->agent('Mozilla/5.0');
    $req = HTTP::Request->new(GET => $url.'archivoParaError403.php');
    $res403 = $ua->request($req);
    print "\tURL para generar error 404: ".$url."archivoParaError403.php\n";
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


sub revisaDiccionario{
    my ($url, $dicFile) = @_;
    my ($ua, $res, $req, $urlDir);

    print "Analisis de diccionario:\n";
    $ua = LWP::UserAgent->new();
    $ua->agent('Mozilla/5.0');

    open (DIRECTORIOS, $dicFile)
	or die "No se puede abrir el archivo de contrasenias\n";

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


sub analizaEncabezado{
    my $resp = shift @_;

    # Muestra todos los encabezados
    #print $res->headers()->as_string()."\n\n";
    print "Analisis de encabezados:\n\n";
    print "Cabecera Server: \n";
    if ($res->header('Server'))
    {
	print "\tValor devuelto: ".$res->header('Server')."\n";
    }
    print "\tDiagnostico: ";
    if ($res->header('Server') =~ /^Apache.*[0-9]+[a-zA-Z]*/){
	print "Server Tokens mal configurados\n";
	print "\tRecomendacion: incluir 'ServerTokens Prod' y 'ServerSignature' en la configuracion de Apache para reducir la informacion divulgada.\n\n";
    }
    else {
	print "ServerTokens configurados.\n\n";
    }
    print "Cabecera X-Powered-By\n";
    if ($res->header('X-Powered-By'))
    {
	print "\tValor devuelto: ".$res->header('X-Powered-By')."\n";
	print "\tDiagnostico X-Powered-By habilitado.\n";
	print "\tRecomendacion: deshabilitar esta opcion para reducir la informacion divulgada del servidor.\n\n";
    }
    else
    {
	print "\tDiagnostico: Cabecera X-Powered-By deshabilitada.\n\n";
    }
    print "Cabecera X-XSS-Protection:\n";
    if ($res->header('X-XSS-Protection'))
    {
	print "\tValor devuelto: ".$res->header('X-XSS-Protection')."\n\n";
	print "\tDiagnostico: X-XSS-Protection habilitada.\n";
    }
    else
    {
	print "\tDiagnostico: X-XSS-Protection no esta habilitada.\n";
	print "\tRecomendacion: habilitar el encabezado 'X-XSS-Protection: 1;mode=block' para reducir el riesgo de ataques de tipo XSS.\n\n";
    }
    print "Cabecera X-Frame-Options:\n";
    if ($res->header('X-Frame-Options'))
    {
	print "\tValor devuelto: ".$res->header('X-Frame-Options')."\n";
	print "\tDiagnostico: X-Frame-Options esta habilitada.\n\n";
    }
    else
    {
	print "\tDiagnostico: X-Frame-Options no esta habilitada.\n";
	print "\tRecomendacion: habilitar 'X-Frame-Options: SAMEORIGIN' para reducir el riesgo de ataques de tipo clickjacking.\n\n";	
    }
    if ($res->header('Client-Peer'))
    {
	print "Datos del servidor:\n";
	my @urlPart = split(/:/,$res->header('Client-Peer'));
	print "\tDireccion: ".$urlPart[0]."\n";
	print "\tPuerto: ".$urlPart[1]."\n\n";
    }
    print "Cabecera Accept-Ranges:\n";
    if ($res->header('Accept-Ranges') ne 'none')
    {
	print "\tDiagnostico: Accept-Ranges habilitada, el servidor puede aceptar peticiones parciales.\n\n";
    }
    else
    {
	print "\tDiagnostico: Accept-Ranges deshabilitada, el servidor no acepta peticiones parciales.\n\n";
    }
}


sub verificaIndexes{
    
}


sub procesaOpciones {
    my ($op, $p) = @_;
    
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




