#!/usr/bin/perl
#
# Mario Arturo Perez Rangel
# Jose Luis Torres Rodriguez
# Version: 0.1
#
use warnings;
use strict;
use Term::ReadKey;
use MIME::Base64;
use Getopt::Long;
use IO::Socket::SSL;
use HTTP::Request;
use LWP::UserAgent;
use HTML::TreeBuilder;

my %params = (loop => 0);
my %opciones;
my %sslopts=();
#my %sslopts=(SSL_verify_mode => SSL_VERIFY_NONE,
#	     verify_hostname => 0,
#	     SSL_ca_path => IO::Socket::SSL::default_ca(),);

GetOptions (\%opciones, 'help|h', 'ip|s=s', 'dict|d=s', 'report|r',
	                'login|l=s', 'password|p=s', 'url=s',
	    );

if ($opciones{help}){
    muestraAyuda();
    exit (1);
}


procesaOpciones(\%opciones, \%params);
adjustParams(\%params, \%sslopts);


my $ua = LWP::UserAgent->new ( ssl_opts => \%sslopts );
my $req = HTTP::Request->new ('GET' => $params{url});
my $res = $ua->request($req);

my $tree = HTML::TreeBuilder->new_from_content($res->content);
my @ah = $tree->look_down ('_tag', 'a', 'href', qr/.+/);
my @im = $tree->look_down ('_tag', 'img', 'src', qr/.+/);
#for my $k (@ah) {
#    print $k->attr('href'), "\n";
#}
for my $k (@im) {
    print $k->attr('src'), "\n";
}
# Hacemos peticiones con el metodo HEAD hasta determinar si en la url proporcionada
# el servidor despacha moodle, o se redirecciona a un sitio con SSL. Tambien se detecta
# si el certificado del servidor es emitido por alguna CA valida. Si es autofirmado o
# presenta problemas saltamos la validacion del certificado.
sub adjustParams {
    my ($p, $ssl) = @_;
    my ($ua, $req, $res);
    
    if ($p->{loop}++ > 6){  # Contamos el numero de veces que se ha llamado la funcion
	print "Demasiados intentos de ajustar los parametros de conexion.\n";
	exit (-1);
    }
    $ua = LWP::UserAgent->new( ssl_opts => $ssl );

    $ua->agent('Mozilla/5.0');

    $req = HTTP::Request->new(HEAD => $params{url});
    $res = $ua->request($req);

    # Vemos la respuesta del servidor
    if ($res->code == 200) { # Todo bien
	$p->{loop} = 0;
	return;
    } elsif ($res->code == 301 or $res->code == 302)  { # Redirecciona a otro recurso
	my $location = $res->headers->{'location'};
	if ($location =~ m|^(https?)(://)([\w\d._-]+)(:\d+)?(/.*)$|) {  # Es una URL?
	    $p->{scheme} = $1;
	    $p->{host} = $3;
	    if ($4) {
		$p->{port} = $4;
		$p->{port} =~ s/^://;
	    }
	    $p->{uri} = $5;
	} elsif ($location =~ m|^/.*|) {   # Es la ruta de un nuevo recurso ?
	    $p->{uri} = $location;
	    $p->{url} = join '', $p->{scheme}, '://', $p->{host},
	                         ($p->{port}) ? ':'.$p->{port} : '',
                                 $p->{uri};
	} else { # Es el nombre de otro recurso
	    $p->{url} =~ s|/([^/]+)$|/$location|;
	    $p->{uri} =~ s|/([^/]+)$|/$location|;
	}
    } elsif ($res->code == 403) {  # No tenemos acceso al recurso
	print "No se tiene acceso a este recurso.\n";
	exit (-1);
    } elsif ($res->code == 500) {
	if ($res->status_line =~ /certificate verify failed/) {  # No se pudo verificar el emisor del certificado
	    $ssl->{SSL_verify_mode} = SSL_VERIFY_NONE;
	    $ssl->{verify_hostname} = 0;
	    adjustParams($p, $ssl);            # Intentamos acceder al recurso sin verificar el certificado
	}
    }
}

##
## Manejo de las opciones en linea de comandos.
## Recibe: dos hashes, uno con las opciones recibidas en linea de comandos y
## un segundo hash con las parametros a pasar a las funciones try_Basic, try_Digest y try_Forma
##
## Regresa el hash de parametros modificados
##
sub procesaOpciones {
    my ($op, $p) = @_;

    if ($op->{ip} and $op->{url}) { # Solo se puede usar una, tomaremos url por default.
	print "Ignorando la direccion ip.\n";
	$p->{ip} = 0;
    }

    if ($op->{dict}) {
	my $nl = (stat $op->{dict})[3];
	$nl = 0 if (!$nl);
	if ($nl <= 0) {
	    print "No existe el archivo con el diccionario.\n";
	    exit(1);
	}
	$p->{dict} = $op->{dict};
    }

    # En vez de nombre de dominio se paso una ip
    if ($op->{ip}){
	 # Es una direccion ip valida?
	if ($op->{ip} =~ /^\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b$/) {
	    $p->{scheme} = 'http';
	    $p->{host} = $op->{ip};
	    $p->{uri} = '/';
	    $p->{url} = join '', 'http://', $op->{ip}, '/';
	} else {
	    print "Debe proporcionar una direccion ip valida.\n";
	    exit (3);
	}
    }

    # La url del moodle
    if ($op->{url}){
	# Desmenuza la url en schema, host, puerto y uri
	if ($op->{url} =~ m|^(https?)(://)([\w\d._-]+)(:\d+)?(/.*)$|) {
	    $p->{scheme} = $1;
	    $p->{host} = $3;
	    if ($4) {
		$p->{port} = $4;
		$p->{port} =~ s/^://;
	    }
	    $p->{uri} = $5;
	    $p->{url} = $op->{url};
	} else {
	    print "La url no tiene el formato requerido.\n";
	    print "Debe ser de la forma:\n";
	    print "                      http(s)://host(:puerto)/<ruta del recurso>\n";
	    print "Ejemplo:\n";
	    print "         https:///my.moodle.com/login.php\n";
	    exit (4);
	}
    }

    # Bandera para indicar la generacion de un reporte
    if($op->{report}) {
	$p->{report} = 1;
    }

    # Manejo de login y password.
    if ($op->{login} and $op->{password}) {
	if ($op->{login} =~ /^(?:[\w\d._-]+@)?[\w\d._-]+$/) {
	    $p->{login} = $op->{login};
	} else {
	    print "El login no tiene un formato valido.\n";
	    exit (2);
	}
	if ($op->{password} =~ /^[\w\d._,;:]+$/) {
	    $p->{password} = $op->{password};
	} else {
	    print "No parece ser un password valido\n";
	    exit (3);
	}
    } elsif ($op->{login} and !$op->{password}) {
	if ($op->{login} =~ /^(?:[\w\d._-]+@)?[\w\d._-]+$/) {
	    $p->{login} = $op->{login};

	    ReadMode ('noecho');
	    print "Password: ";
	    chomp($op->{password} = <STDIN>);
	    ReadMode ('restore');
	    if ($op->{password} eq '') {
		print "No puede usar un password vacio.\n";
		exit (4);
	    }
	    if ( !($op->{password} =~ /[\w\d._,;:]+/) ) {
		print "No parece ser un password valido.\n";
		exit (5);
	    }
	}
    } elsif ( $op->{password} and !$op->{login} ){
	print "Necesita un login para ese password\n";
	exit (6);
    }

    return $p;
}

##
## muestraAyuda muestra al usuario como se debe usar este programa.
##
sub muestraAyuda {
}

