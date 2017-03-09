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
my $reqSSL = HTTP::Request->new(GET => 'https://aula.cert.unam.mx/');
#my $req = HTTP::Request->new(GET => 'http://192.168.13.149/');
my $res = $uaSSL->request($reqSSL);
#my $res = $ua->request($req);

if ($res->is_success) { 
    analizaEncabezado(\$res);
}
else {
    print "Failed: ", $res->status_line, "\n";
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



#http://search.cpan.org/~ether/HTTP-Message-6.11/lib/HTTP/Response.pm
#http://search.cpan.org/~oalders/libwww-perl-6.23/lib/LWP/UserAgent.pm
#http://stackoverflow.com/questions/4022463/how-can-i-extract-non-standard-http-headers-using-perls-lwp
#http://search.cpan.org/~ether/HTTP-Message-6.11/lib/HTTP/Headers.pm
#http://search.cpan.org/~ether/HTTP-Message-6.11/lib/HTTP/Message.pm
###
#http://lwp.interglacial.com/ch03_05.htm
