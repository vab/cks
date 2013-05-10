Summary: CryptNET OpenPGP Keyserver
Name: cks
Version: 0.2.4
Release: 1
Copyright: Gnu General Public License [GPL]
Group: Security/Cryptography
URL: http://www.cryptnet.net/fsp/cks/
Source: http://www.cryptnet.net/fsp/cks/cks-0.2.4.tar.gz
Buildroot: /var/tmp/%{name}-%{version}-%{release}
Prefix: /usr/local

%description
  This is version %{version} of the CryptNET Keyserver.  This is an
  RFC4880 compliant PGP keyserver which uses postgres for key storage.

%prep
rm -rf $RPM_BUILD_ROOT

%setup -q


%build
CFLAGS="$RPM_OPT_FLAGS" CXXFLAGS="$RPM_OPT_FLAGS" ./configure \
--prefix=%{prefix}
make
#-j2

%install
make install prefix=$RPM_BUILD_ROOT/%{prefix}

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,0755)

