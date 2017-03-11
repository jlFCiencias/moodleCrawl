#!/usr/bin/perl
#
# Mario Arturo Perez Rangel
# Jose Luis Torres Rodriguez
# Version: 1.0
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
 
$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;

my %params = (loop => 0);
my (%options, %dir_found, %sslopts);
my (@url_to_visit, @visited_url);
my ($ua, $url, $tipoSalida, $archivoSalida, $dicFile);

GetOptions (\%options, 'help|h', 'ip|s=s', 'dict|d=s', 'report|r=s',
	                'login|l=s', 'password|p=s', 'url=s', 'debug',
	    );

if ($options{help}){
    muestraAyuda();
    exit (1);
}

processOptions(\%options, \%params);


if ($params{report}){
    $tipoSalida = $params{report};
}

    print $tipoSalida."\n";

if ($tipoSalida eq 'html'){
    $archivoSalida="moodleCrawlOUT.html";
    encabezadoHTML($archivoSalida);
}
else
{
    $archivoSalida="moodleCrawlOUT.txt";
}

if (adjustParams(\%params, \%sslopts) == -1 ) {
    exit (-1);
}

$ua = LWP::UserAgent->new ( ssl_opts => \%sslopts );
$ua->agent('Mozilla/5.0');

my $req = HTTP::Request->new(GET => $params{url});

my $res = $ua->request($req);


($tipoSalida eq 'html')? agregaArchivo($archivoSalida, "<p>Codigo de respuesta: ".$res->code."</p>\n") : agregaArchivo($archivoSalida, "Codigo de respuesta: ".$res->code."\n\n");

if ($res->is_success) { 
    # Revisamos los encabezados, pasamos el resultado HTTP, el nombre del archivo de salida y el formato de esta
    analizaEncabezado($res, $archivoSalida, $tipoSalida);
}
else {
    ($tipoSalida eq 'html')? agregaArchivo($archivoSalida, "<p>Failed: ".$res->status_line."</p>\n") : agregaArchivo($archivoSalida, "Failed: ", $res->status_line, "\n");
}

# Revisamos la respuesta a los errores 403, 404 y 500
analizaCodigosError($params{url}, $archivoSalida, $tipoSalida);

if ($params{dict})
{
   $dicFile = $params{dict}; 
   # Hacemos la revisión de los directorios contenidos en el diccionario
   revisaDiccionario($params{url}, $dicFile, $archivoSalida, $tipoSalida);
}

$ua = LWP::UserAgent->new ( ssl_opts => \%sslopts );
$ua->agent('Mozilla/5.0');

if ($params{login} eq 'guest') {
    if (getGuestConnected($ua, \%params) == -1) {
	($tipoSalida eq 'html')? agregaArchivo($archivoSalida, "<p>Error: no existe el usuario guest.</p>\n") : agregaArchivo($archivoSalida, "Error: no existe el usuario guest.\n");
    }
}

if ($params{login} eq 'guest') {
    if (getGuestConnected($ua, \%params) == -1) {
	($tipoSalida eq 'html')? agregaArchivo($archivoSalida, "<p>Error: no existe el usuario guest.</p>\n") : agregaArchivo($archivoSalida, "Error: no existe el usuario guest.\n");      
    }
}
else {
    getConnected($ua, \%params);
}

push @url_to_visit, $params{url};

#print $params{'clheaders'}->{'Cookie'}, "\n";
while (@url_to_visit) {
    $url = shift @url_to_visit;
    push @visited_url, $url;
    print "Visiting ", $url, "...\n" if ($options{debug});
    visitUrl ($ua, $url, \%params, \%sslopts,  \%dir_found, \@url_to_visit, \@visited_url);
#    print @url_to_visit, "\n";
}

($tipoSalida eq 'html')? agregaArchivo($archivoSalida, "<p><h2>Busqueda de directorios</h2></p>\n") : agregaArchivo($archivoSalida, "Busqueda de directorios\n\n");

agregaArchivo($archivoSalida, join("\n", keys %dir_found));

pieHTML($archivoSalida);

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
	$form->delete;
    }
    $tree->delete;
    
    #
    # Preparamos una nueva solicitud con los resultados obtenidos
    #
    $req->clear();
    $req->method('POST');
    $req->uri($login);
    for $hn (keys %{$p->{'clheaders'}}) {    # Agregamos las cabeceras necesarias a la peticion
	$req->header($hn => $p->{'clheaders'}->{$hn});
    }
    $req->header('Host' => $p->{host});
    $req->header('Referer' => $login);
    $req->header('Upgrade-Insecure-Requests' => 1);
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
    } elsif ($res->code >= 300 and $res->code <= 303) {
	if ($res->headers->{'set-cookie'}) {
	    if (ref ($res->headers->{'set-cookie'}) eq "ARRAY") {
		$p->{'clheaders'}->{'Cookie'} = join '; ', @{$res->headers->{'set-cookie'}};
	    } else {
		$p->{'clheaders'}->{'Cookie'} = $res->headers->{'set-cookie'};
	    }
	}
    } else {
	return -1;
    }
    #
    # Prepara una nueva peticion para obtener una llave de sesion
    #
    $req->clear();
    $req->method('GET');
    $req->uri($p->{url}.'/user/policy.php');
    for $hn (keys %{$p->{'clheaders'}}) {    # Agregamos las cabeceras necesarias a la peticion
	$req->header($hn => $p->{'clheaders'}->{$hn});
    }
    $res = $myua->request($req);

    if ($res->code >= 400) {
	return -1;
    }

    if ($res->headers->{'set-cookie'}) {
	if (ref ($res->headers->{'set-cookie'}) eq "ARRAY") {
	    $p->{'clheaders'}->{'Cookie'} = join '; ', @{$res->headers->{'set-cookie'}};
	} else {
	    $p->{'clheaders'}->{'Cookie'} = $res->headers->{'set-cookie'};
	}
    }
    $tree = HTML::TreeBuilder->new_from_content($res->content);
    $form = $tree->look_down('_tag', 'form');
	
    #
    # Prepara una nueva peticion para obtener una llave de sesion
    #
	$req->clear();
    $req->method('POST');
    $req->uri($p->{url}.'/user/policy.php');
    for $hn (keys %{$p->{'clheaders'}}) {    # Agregamos las cabeceras necesarias a la peticion
	$req->header($hn => $p->{'clheaders'}->{$hn});
    }
    $res = $myua->request($req);
    print $res->content;

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

    if ($res->headers->{'set-cookie'}) {
	if (ref ($res->headers->{'set-cookie'}) eq "ARRAY") {
	    $p->{'clheaders'}->{'Cookie'} = join '; ', @{$res->headers->{'set-cookie'}};
	} else {
	    $p->{'clheaders'}->{'Cookie'} = $res->headers->{'set-cookie'};
	}
    }
    return 1;
}

#
# Intenta generar los errores 403, 404 y 500 en el equipo analizado y muestra los resultados obtenidos
# Tambien despliega una recomendacion de seguridad, en caso de ser necesario.
#
sub analizaCodigosError{
    my ($url, $fileOut, $tipoSalida) = @_; # Recibimos la URL, el nombre del archivo de salida y el tipo de salida a generar

    # Intentamos abrir el archivo de salida para agregar informacion
    open(SALIDA, ">>", $fileOut)
	or die "No se puede abrir el archivo para agregar la salida.";

    my ($ua, $res403, $res404, $res500, $req, $urlErr);

    ($tipoSalida eq 'html')? print SALIDA "<p><h2>Analisis de errores</h2></p>\n" : print SALIDA "Analisis de errores\n\n";

    # Error 403
    ($tipoSalida eq 'html')? print SALIDA "<p>Analisis de error 403:</p>\n<table border=1>\n" : print SALIDA "Analisis de error 403:\n";
    
    # Si el protocolo es https deshabilitamos la verificacion de certificados
    $ua = ($url =~ /https:\/\/.*/) ? LWP::UserAgent->new( ssl_opts => { SSL_verify_mode => 'SSL_VERIFY_NONE' } ) : LWP::UserAgent->new();

    $ua->agent('Mozilla/5.0');
    $urlErr = $url.'user/filesedit.php';
    $req = HTTP::Request->new(GET => $urlErr);
    $res403 = $ua->request($req);
    ($tipoSalida eq 'html')? print SALIDA "<tr><td class='celdaNom'>URL utilizada</td><td class='celdaTexto'>".$urlErr."</td></tr>\n" : print SALIDA "\tURL utilizada: ".$urlErr."\n";
    ($tipoSalida eq 'html')? print SALIDA "<tr><td class='celdaNom'>Codigo de respuesta</td><td class='celdaTexto'>".$res403->code."</td></tr>\n" : print SALIDA "\tCodigo de respuesta: ".$res403->code."\n";
    if (grep(/Apache\/.*[0-9]+\.[0-9]+/, $res403->content))
    {
	($tipoSalida eq 'html')? print SALIDA "<tr><td class='celdaNom'>Diagnostico</td><td class='celdaTexto'>El servidor revela informacion que deberia mantenerse como privada</td></tr>\n" : print SALIDA "\tDiagnostico: el servidor revela informacion que deberia mantenerse como privada.\n";
	($tipoSalida eq 'html')? print SALIDA "<tr><td class='celdaNom'>Recomendacion</td><td class='celdaTexto'>Incluir 'ServerTokens Prod' y 'ServerSignature' en la configuracion de Apache para reducir la informacion divulgada.<br />Tambien se dede definir la respuesta para el error 403 en el servidor Web.</td></tr></table>\n" : print SALIDA "\tRecomendacion: incluir 'ServerTokens Prod' y 'ServerSignature' en la configuracion de Apache para reducir la informacion divulgada.\n\tTambien se dede definir la respuesta para el error 403 en el servidor Web\n\n";
    }
    else
    {
	($tipoSalida eq 'html')? print SALIDA "<tr><td class='celdaNom'>Diagnostico</td><td class='celdaTexto'>El servidor no revela informacion privada</td></tr></table>\n" : print SALIDA "\tDiagnostico: el servidor no revela informacion privada.\n\n";
    }

    # Error 404
    ($tipoSalida eq 'html')? print SALIDA "<p>Analisis de error 404:</p>\n<table border=1>\n" : print SALIDA "Analisis de error 404:\n";

    # Si el protocolo es https deshabilitamos la verificacion de certificados
    $ua = ($url =~ /https:\/\/.*/) ? LWP::UserAgent->new( ssl_opts => { SSL_verify_mode => 'SSL_VERIFY_NONE' } ) : LWP::UserAgent->new();

    $ua->agent('Mozilla/5.0');
    $urlErr = $url.'course/index.php?categoryid=-9';
    $req = HTTP::Request->new(GET => $urlErr);
    $res404 = $ua->request($req);
    ($tipoSalida eq 'html')? print SALIDA "<tr><td class='celdaNom'>URL utilizada</td><td class='celdaTexto'>".$urlErr."</td></tr>\n" : print SALIDA "\tURL utilizada: ".$urlErr."\n";
    ($tipoSalida eq 'html')? print SALIDA "<tr><td class='celdaNom'>Codigo de respuesta</td><td class='celdaTexto'>".$res404->code."</td></tr>\n" : print SALIDA "\tCodigo de respuesta: ".$res404->code."\n";
    if (grep(/Apache\/.*[0-9]+\.[0-9]+/, $res404->content))
    {
	($tipoSalida eq 'html')? print SALIDA "<tr><td class='celdaNom'>Diagnostico</td><td class='celdaTexto'>El servidor revela informacion que deberia mantenerse como privada</td></tr>\n" : print SALIDA "\tDiagnostico: el servidor revela informacion que deberia mantenerse como privada.\n";
	($tipoSalida eq 'html')? print SALIDA "<tr><td class='celdaNom'>Recomendacion</td><td class='celdaTexto'>incluir 'ServerTokens Prod' y 'ServerSignature' en la configuracion de Apache para reducir la informacion divulgada<br />Tambien se dede definir la respuesta para el error 404 en el servidor Web.</td></tr></table>\n" : print SALIDA "\tRecomendacion: incluir 'ServerTokens Prod' y 'ServerSignature' en la configuracion de Apache para reducir la informacion divulgada.\n\tTambien se dede definir la respuesta para el error 404 en el servidor Web\n\n";
    }
    else
    {
	($tipoSalida eq 'html')? print SALIDA "<tr><td class='celdaNom'>Diagnostico</td><td class='celdaTexto'>El servidor no revela informacion privada</td></tr></table>\n" : print SALIDA "\tDiagnostico: el servidor no revela informacion privada.\n\n";
    }

    # Error 500
    ($tipoSalida eq 'html')? print SALIDA "<p>Analisis de error 500:</p>\n<table border=1>\n" : print SALIDA "Analisis de error 500:\n";
    $ua = LWP::UserAgent->new();
    $ua->agent('Mozilla/5.0');
    $urlErr = $url.'version.php';
    $req = HTTP::Request->new(GET => $urlErr);
    $res500 = $ua->request($req);
    ($tipoSalida eq 'html')? print SALIDA "<tr><td class='celdaNom'>Metodo y URL</td><td class='celdaTexto'>GET ".$urlErr."</td></tr>\n" : print SALIDA "\tMetodo y URL: GET ".$urlErr."\n\n";
    ($tipoSalida eq 'html')? print SALIDA "<tr><td class='celdaNom'>Codigo de respuesta</td><td class='celdaTexto'>".$res500->code."</td></tr>\n" : print SALIDA "\tCodigo de respuesta: ".$res500->code."\n";
    if (grep(/Apache\/.*[0-9]+\.[0-9]+/, $res500->content))
    {
	($tipoSalida eq 'html')? print SALIDA "<tr><td class='celdaNom'>Diagnostico</td><td class='celdaTexto'>El servidor revela informacion que deberia mantenerse como privada</td></tr>\n" : print SALIDA "\tDiagnostico: el servidor revela informacion que deberia mantenerse como privada.\n";
	($tipoSalida eq 'html')? print SALIDA "<tr><td class='celdaNom'>Recomendacion</td><td class='celdaTexto'>incluir 'ServerTokens Prod' y 'ServerSignature' en la configuracion de Apache para reducir la informacion divulgada<br />Tambien se dede definir la respuesta para el error 500 en el servidor Web.</td></tr></table>\n" : print SALIDA "\tRecomendacion: incluir 'ServerTokens Prod' y 'ServerSignature' en la configuracion de Apache para reducir la informacion divulgada.\n\tTambien se dede definir la respuesta para el error 500 en el servidor Web\n\n";
    }
    else
    {
	($tipoSalida eq 'html')? print SALIDA "<tr><td class='celdaNom'>Diagnostico</td><td class='celdaTexto'>El servidor no revela informacion privada</td></tr></table>\n" : print SALIDA "\tDiagnostico: el servidor no revela informacion privada.\n\n";
    }
    close (SALIDA);
}


#
# Hace una revision de los directorios del archivo que contiene el diccionario en el servidor analizado, 
# en caso de que el usuario lo indique.
#
sub revisaDiccionario{ 
    # Recibimos la url a analizar, el nombre del diccionario, el nombre del archivo de salida y el tipo de salida
    my ($url, $dicFile, $fileOut, $tipoSalida) = @_; 
    my ($ua, $res, $req, $urlDir, $finURL);

    # Si el protocolo es https deshabilitamos la verificacion de certificados
    $ua = ($url =~ /https:\/\/.*/) ? LWP::UserAgent->new( ssl_opts => { SSL_verify_mode => 'SSL_VERIFY_NONE' } ) : LWP::UserAgent->new();

    $ua->agent('Mozilla/5.0');

    # Intentamos abrir el diccionario
    open (DIRECTORIOS, $dicFile)
	or die "No se puede abrir el archivo de contrasenias\n";

    # Intentamos abrir el archivo de salida para agregar informacion  
    open(SALIDA, ">>", $fileOut)
        or die "No se puede abrir el archivo para agregar la salida.";

    if (substr($url, -1) eq '/'){
	chop($url);
    }
    ($tipoSalida eq 'html')? print SALIDA "<p><h2>Analisis de diccionario</h2></p>\n<table class='sinBorde'>\n" : print SALIDA "Analisis de diccionario:\n\n";
    # Intentamos cada uno de los directorios en el servidor y revisamos los codigos 
    # devueltos para la peticion HTTP
    while (<DIRECTORIOS>) {
	chomp($_);
	if ($_ =~ /\/.*/){
	    $urlDir = $url.$_;
	}
	else 
	{
	    $urlDir = $url.'/'.$_;
	}
	$req = HTTP::Request->new(GET => $urlDir);
	$res = $ua->request($req);
	($tipoSalida eq 'html')? print SALIDA "<tr><td>".$urlDir."</td>\n" : print SALIDA "$urlDir\n";
	($tipoSalida eq 'html')? print SALIDA "<td></td>\n" : print SALIDA "\tDiagnostico: ";
	if ($res->code == 200){
	    ($tipoSalida eq 'html')? print SALIDA "<td>El directorio existe</td></tr>\n" : print SALIDA "El directorio existe.\n\n";
	}
	else{
	    if ($res->code == 403){
		($tipoSalida eq 'html')? print SALIDA "<td>Existe pero se requieren privilegios para acceder</td></tr>\n" : print SALIDA "Existe pero se requieren privilegios para acceder.\n\n";
	    }
	    else{
		if ($res->code == 404){
		    ($tipoSalida eq 'html')? print SALIDA "<td>No existe o no se puede acceder</td></tr>\n" : print SALIDA "No existe o no se puede acceder.\n\n";
		}
		else{
		    if ($res->code >= 300 && $res->code < 400){
			($tipoSalida eq 'html')? print SALIDA "<td>La peticion fue redirigida</td></tr>\n" : print SALIDA "La peticion fue redirigida.\n\n";
		    }
		    else{
			($tipoSalida eq 'html')? print SALIDA "<td>El servidor reporto el error ".$res->code."</td></tr>\n" : print SALIDA "El servidor reporto el error ".$res->code."\n\n";
		    }
		}
	    }
	}
    }
    close (DIRECTORIOS);
    close (SALIDA);
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

    ($tipoSalida eq 'html')? print SALIDA "<p><h2>Analisis de encabezados</h2></p>\n" : print SALIDA "Analisis de encabezados:\n\n";

    # Mostramos los datos del servidor
    if ($res->header('Client-Peer'))
    {
	($tipoSalida eq 'html')? print SALIDA "<p>Datos del servidor: </p>\n<table border=1>\n" : print SALIDA "Datos del servidor:\n";
	my @urlPart = split(/:/,$res->header('Client-Peer'));
	($tipoSalida eq 'html')? print SALIDA "<tr><td class='celdaNom'>Direccion</td><td class='celdaTexto'>".$urlPart[0]."</td></tr>" : print SALIDA "\tDireccion: ".$urlPart[0]."\n";
	($tipoSalida eq 'html')? print SALIDA "<tr><td class='celdaNom'>Puerto</td><td class='celdaTexto'>".$urlPart[1]."</td></tr></table>\n" : print SALIDA "\tPuerto: ".$urlPart[1]."\n";
    }

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
	($tipoSalida eq 'html')? print SALIDA "<td class='celdaNom'>ServerTokens configurados.</td></tr></table>\n" : print SALIDA "ServerTokens configurados.\n\n";
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
    print SALIDA "<title>Moodle Crawler y divulgacion de informacion</title>\n";
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
    print SALIDA "<br /><br /></body>\n";
    print SALIDA "</html>\n";
    close (SALIDA);
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
	if (($op->{report} ne 'html') and ($op->{report} ne 'text')){
	    $p->{report} = 'text';
	}
	else {
	    $p->{report} = $op->{report}; 
	}
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

