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
my (%options, %dir_found, %sslopts);
my (@url_to_visit, @visited_url);
my ($ua, $url);
#my %sslopts=(SSL_verify_mode => SSL_VERIFY_NONE,
#	     verify_hostname => 0,
#	     SSL_ca_path => IO::Socket::SSL::default_ca(),);

GetOptions (\%options, 'help|h', 'ip|s=s', 'dict|d=s', 'report|r',
	                'login|l=s', 'password|p=s', 'url=s', 'debug',
	    );

if ($options{help}){
    muestraAyuda();
    exit (1);
}


processOptions(\%options, \%params);
if (adjustParams(\%params, \%sslopts) == -1 ) {
    exit (-1);
}

$ua = LWP::UserAgent->new ( ssl_opts => \%sslopts );
$ua->agent('Mozilla/5.0');


if ($params{login} eq 'guest') {
    if (getGuestConnected($ua, \%params) == -1) {
	exit (-1);
    }
}
#} else {
#    getConnected(\%params);
#}

push @url_to_visit, $params{url};

print $params{'clheaders'}->{'Cookie'}, "\n";
while (@url_to_visit) {
    $url = shift @url_to_visit;
    push @visited_url, $url;
    print "Visiting ", $url, "...\n" if ($options{debug});
    visitUrl ($ua, $url, \%params, \%sslopts,  \%dir_found, \@url_to_visit, \@visited_url);
#    print @url_to_visit, "\n";
}
my $n = keys %dir_found;
#print "Numero de entradas: ", $n, "\n";
for my $k (sort keys %dir_found) {
    print $k , "\n";
}

##
## visitUrl
##
sub visitUrl {
    my ($myua, $url, $p, $sslopts, $dirs, $tovisit, $visited) = @_;
    my ($req, $res, $tree, $k, @links);

    $req = HTTP::Request->new ('GET' => $url);
    for my $hn (keys %{$p->{'clheaders'}}) {    # Agregamos las cabeceras necesarias a la peticion
	$req->header($hn => $p->{'clheaders'}->{$hn});
    }
    $res = $myua->request($req);


    if ($res->code >= 200 and $res->code < 300) { # Recordar la(s) cookies recibida(s)
	$p->{'clheaders'}->{'Cookie'} = $res->headers->{'set-cookie'} if ($res->headers->{'set-cookie'});
    } else {
	print 'DEBUG >> ', "El servidor respondio con el codigo ", $res->code, "\n" if ($options{debug});
	return;
    }
    $tree = HTML::TreeBuilder->new_from_content($res->content);

    @links = $tree->look_down ('_tag', 'a', 'href', qr/.+/);
    push @links, $tree->look_down ('_tag', 'link', 'href', qr/.+/);
    for $k (@links) { # Busca y revisa todas las ligas dentro del sitio
	my $href = $k->attr('href');
	#print $href, "\n";
	if ($href =~ m|^$p->{url}([\w\d\._/-]+)/(\w+)\.php.*$|) {
	    if (!$dirs->{$1}) {
		$dirs->{$1} = 1;
	    }
	    if ( ! checkURLIn ($visited, $href)) {
		push @$tovisit, $href;
	    }
	} else {
	    print 'DEBUG >> ', $href, "\n" if ($options{debug});
	}
    }

    $#links = -1;
    @links = $tree->look_down ('_tag', 'img', 'src', qr/.+/);
    push @links, $tree->look_down ('_tag', 'script', 'src', qr/.+/);
    for $k (@links) { # Busca y revisa los directorios dentro del atributo 'src' de las imagenes
	my $src = $k->attr('src');
	if ($src =~ m|^$p->{url}([\w\d\._/-]+)/([\w\d_.-]+)\.php.*$|) {
	    if (!$dirs->{$1}) {
		$dirs->{$1} = 1;
	    }
	} else {
	    print 'DEBUG >> ', $src, "\n" if ($options{debug});
	}
    }
    for my $k ($tree->look_down ('_tag', 'form')) {
	print 'DEBUG f>> ', $k->attr('action'), "\n" if ($options{debug});
    }
}

#
# Determina si la url encontrada ya se visito
sub checkURLIn {
    my ($aref, $entry) = @_;
    my ($e, $mye) = ('', $entry);

    for $e (@$aref) {
	$e =~ s|^(.*)/([\w\d._-]+)\.php.*$|$1/$2.php|;
	$mye =~ s|^(.*)/([\w\d._-]+)\.php.*$|$1/$2.php|;
	#print '<<1>> ', $e, "\n", '<<2>> ', $mye, "\n\n";
	return 1 if ($mye eq $e);
    }
    return 0;
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
	return 1;
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
	return (adjustParams($p, $ssl));     # Intentamos acceder recurso mencionado por la cabecera Location
    } elsif ($res->code == 403) {  # No tenemos acceso al recurso
	print "No se tiene acceso a este recurso.\n";
	return (-1);
    } elsif ($res->code == 500) {
	if ($res->status_line =~ /certificate verify failed/) {  # No se pudo verificar el emisor del certificado
	    $ssl->{SSL_verify_mode} = SSL_VERIFY_NONE;
	    $ssl->{verify_hostname} = 0;
	    return (adjustParams($p, $ssl));            # Intentamos acceder al recurso sin verificar el certificado
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
sub processOptions {
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

    # Entraremos a moodle como usuario guest
    } else {
	$p->{login} = 'guest';
	$p->{password} = 'guest';
    }

    return $p;
}

##
## muestraAyuda muestra al usuario como se debe usar este programa.
##
sub muestraAyuda {
}

##
## getGuestConnected
##
sub getGuestConnected {
    my ($myua, $p) = @_;
    my ($req, $res, $login, $hn);
    my ($tree, $form, $content, $submit, @inputs);

    $login = join '', $p->{url}, 'login/index.php';

    $req = HTTP::Request->new('GET' => $login);
    $res = $myua->request($req);

    if ($res->code >= 400) {
	return -1;
    }
    $p->{'clheaders'}->{'Cookie'} = $res->headers->{'set-cookie'} if ($res->headers->{'set-cookie'});

    $content = join '&', 'username=guest', 'password=guest';
    $tree = HTML::TreeBuilder->new_from_content ($res->content);
    $form = $tree->look_down ('_tag', 'form', 'id', 'guestlogin');
    if ($form) {
	my $tmp = $form->look_down('_tag', 'input', 'name', 'username');
	$tmp->detach;
	$tmp->delete;
	$tmp = $form->look_down('_tag', 'input', 'name', 'password');
	$tmp->detach;
	$tmp->delete;
	@inputs = $form->look_down('_tag', 'input', 'type', 'text');
	push @inputs, $form->look_down('_tag', 'input', 'type', 'checkbox');
	$submit = $form->look_down('_tag', 'input', 'type', 'submit');

	for my $i (@inputs) {
	    $content = join '&', $content, $i->attr('name').'='.$i->attr('value');
	}
	$content = join '&', $content, 'submit=';
    }
    $tree->delete;
    
    $req = HTTP::Request->new('POST' => $login);
    for $hn (keys %{$p->{'clheaders'}}) {    # Agregamos las cabeceras necesarias a la peticion
	$req->header($hn => $p->{'clheaders'}->{$hn});
    }
    $req->header('Referer' => $login);
    $req->header('Content-Type' => 'application/x-www-form-urlencoded');
    $req->content($content);
    $res = $myua->request($req);

    if ($res->code >= 400) {
	return -1;
    }
    print $res->content, "\n";
    if ($res->code >= 200 and $res->code < 300) {
	if ($res->content =~ /notloggedin/) {
	    return -1;
	}
    } elsif ($res->code >= 300 and $res->code <= 303) {
	if ($res->headers->{'set-cookie'}) {
	    if (ref ($res->headers->{'set-cookie'}) eq "ARRAY") {
		for my $e (@{$res->headers->{'set-cookie'}}) {
		    if ($e =~ /MoodleSession/) {
			$p->{'clheaders'}->{'Cookie'} = $e;
		    }
		}
	    } else {
		$p->{'clheaders'}->{'Cookie'} = $res->headers->{'set-cookie'};
	    }
	}

	$req = HTTP::Request->new('GET' => $res->headers->{'location'});
	for $hn (keys %{$p->{'clheaders'}}) {    # Agregamos las cabeceras necesarias a la peticion
	    $req->header($hn => $p->{'clheaders'}->{$hn});
	}
	$req->headers('Referer' => $login);
	$res = $myua->request($req);
	print $res->code, "\n";
#	print $res->content;
    }

    return 1;
}

##
## getConnected
##
sub getConnected {
    my ($myua, $p) = @_;
    my ($req, $res, $login, $hn);
    my ($tree, $form, $content, $submit, @inputs);

    $login = join '', $p->{url}, 'login/index.php';

    $req = HTTP::Request->new('GET' => $login);
    $res = $myua->request($req);

    if ($res->code >= 400) {
	return -1;
    }
    $p->{'clheaders'}->{'Cookie'} = $res->headers->{'set-cookie'} if ($res->headers->{'set-cookie'});

    $content = join '&', 'username='.$p->{login}, 'password='.$p->{password};
    $tree = HTML::TreeBuilder->new_from_content ($res->content);
    $form = $tree->look_down ('_tag', 'form', 'id', 'guestlogin');
    if ($form) {
	my $tmp = $form->look_down('_tag', 'input', 'name', 'username');
	$tmp->detach;
	$tmp->delete;
	$tmp = $form->look_down('_tag', 'input', 'name', 'password');
	$tmp->detach;
	$tmp->delete;
	@inputs = $form->look_down('_tag', 'input', 'type', 'text');
	push @inputs, $form->look_down('_tag', 'input', 'type', 'checkbox');
	$submit = $form->look_down('_tag', 'input', 'type', 'submit');

	for my $i (@inputs) {
	    $content = join '&', $content, $i->attr('name').'='.$i->attr('value');
	}
	$content = join '&', $content, 'submit=';
    }
    $tree->delete;
    
    $req = HTTP::Request->new('POST' => $login);
    for $hn (keys %{$p->{'clheaders'}}) {    # Agregamos las cabeceras necesarias a la peticion
	$req->header($hn => $p->{'clheaders'}->{$hn});
    }
    $req->header('Content-Type' => 'application/x-www-form-urlencoded');
    $req->content($content);
    $res = $myua->request($req);

    if ($res->code >= 400) {
	return -1;
    }
    if ($res->code >= 200 and $res->code < 300) {
	if ($res->content =~ /notloggedin/) {
	    return -1;
	}
    }

    $p->{'clheaders'}->{'Cookie'} = $res->headers->{'set-cookie'} if ($res->headers->{'set-cookie'});
    return 1;
}

