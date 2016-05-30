rm(list=ls())

args<-commandArgs(TRUE)

INSTALLED_XMEANS = 0

require(RWeka)
require(mclust)
require(fpc)

WORK_DIR <- args[1]
INPUT_DIR <- 'binning'
OUTPUT_DIR <- 'custering'

CATALOGS <- c( 249 )
INTERVALS <- c( 2, 4, 6, 8, 10, 24 )
ALGORITHMS <- c( 'xmeans', 'dbscan', 'em' )

INPUT_DIR <- paste( WORK_DIR, INPUT_DIR, sep='' );
OUTPUT_DIR <- paste( WORK_DIR, OUTPUT_DIR, sep='' );

SUBS <- new.env( hash = TRUE, parent = emptyenv(), size = length( ALGORITHMS ) )

sub_split <- function( str ) {
	ret <- as.numeric( unlist( strsplit( str, "," ) ) )
	return(ret)
}

sub_interval_length <- function ( str ) {
	ret <- length( sub_split( str ) )
	return(ret)
}

sub_split_criteria <- function ( str, nrow ) {
	ret <- t( matrix(apply(  str, 1, sub_split ), nrow=nrow ) )
	return(ret)
}

SUBS[[ 'xmeans' ]] <- function ( input_dir, output_dir, file_name ) {

	if ( !INSTALLED_XMEANS && require('RWeka') ) {
		print('Running XMeans installing. This operation can take several minutes...')
		WPM("install-package", "XMeans")
		INSTALLED_XMEANS <<- 1;
	}

	msg <- paste( "Running XMeans algorithm for file: ", file_name, sep='' )
	print(msg)

	dir.create( output_dir, showWarnings=FALSE, recursive=TRUE,  mode='755' )
	input_file_name <- paste( input_dir, file_name, sep="/" )
	output_file_name <- paste( output_dir, file_name, sep="/" )

	table <- read.csv( input_file_name, header=T, sep=";", stringsAsFactors=F )

	interval <- sub_interval_length( table$fph[1] )

	fph <- sub_split_criteria( table[4], interval )
	ppf <- sub_split_criteria( table[5], interval )
	bpp <- sub_split_criteria( table[6], interval )
	bps <- sub_split_criteria( table[7], interval )

	xmdf <- data.frame(fph=fph, ppf=ppf, bpp=bpp, bps=bps)

	xmclust <- XMeans(xmdf, c("-L", 10, "-H", 100, "-use-kdtree", "-K", "weka.core.neighboursearch.KDTree -P"))

	xmtable <- data.frame(src=table$src_ip, dst=table$dst_ip, port=table$dst_port, fph=table$fph, ppf=table$ppf, bpp=table$bpp, bps=table$bps, cluster_id=xmclust$class_ids)

	write.table(xmtable, file = output_file_name, sep = ";", col.names = NA, qmethod = "double")

	rm(table, interval, fph, ppf, bpp, bps, xmdf, xmclust, xmtable)
}

SUBS[[ 'dbscan' ]] <- function ( input_dir, output_dir, file_name ) {
	msg <- paste( "Running DBSCAN algorithm for file: ", file_name, sep='' )
	print(msg)

	dir.create( output_dir, showWarnings=FALSE, recursive=TRUE,  mode='755' )
	input_file_name <- paste( input_dir, file_name, sep="/" )
	output_file_name <- paste( output_dir, file_name, sep="/" )

	table <- read.csv( input_file_name, header=T, sep=";", stringsAsFactors=F )

	interval <- sub_interval_length( table$fph[1] )

	fph <- sub_split_criteria( table[4], interval )
	ppf <- sub_split_criteria( table[5], interval )
	bpp <- sub_split_criteria( table[6], interval )
	bps <- sub_split_criteria( table[7], interval )

	dbmx <- as.matrix(data.frame(fph=fph, ppf=ppf, bpp=bpp, bps=bps))

	dbclust <- dbscan(dbmx, 1.5, MinPts=4, seed=F)

	dbtable <- data.frame(src=table$src_ip,dst=table$dst_ip,port=table$dst_port,fph=table$fph,ppf=table$ppf,bpp=table$bpp,bps=table$bps,cluster_id=dbclust$cluster)

	write.table(dbtable, file = output_file_name, sep = ";", col.names = NA, qmethod = "double")

	rm(table, interval, fph, ppf, bpp, bps, dbmx, dbclust, dbtable)
}

SUBS[[ 'em' ]] <- function ( input_dir, output_dir, file_name ) {
	msg <- paste( "Running EM algorithm for file: ", file_name, sep='' )
	print(msg)

	dir.create( output_dir, showWarnings=FALSE, recursive=TRUE,  mode='755' )
	input_file_name <- paste( input_dir, file_name, sep="/" )
	output_file_name <- paste( output_dir, file_name, sep="/" )

	table <- read.csv( input_file_name, header=T, sep=";", stringsAsFactors=F )

	interval <- sub_interval_length( table$fph[1] )

	fph <- sub_split_criteria( table[4], interval )
	ppf <- sub_split_criteria( table[5], interval )
	bpp <- sub_split_criteria( table[6], interval )
	bps <- sub_split_criteria( table[7], interval )

	emmx <- as.matrix(data.frame(fph=fph, ppf=ppf, bpp=bpp, bps=bps))
	
	emclust <- Mclust(emmx)

	emtable <- data.frame(src=table$src_ip,dst=table$dst_ip,port=table$dst_port,fph=table$fph,ppf=table$ppf,bpp=table$bpp,bps=table$bps,cluster_id=emclust$classification)

	write.table(emtable, file = output_file_name, sep = ";", col.names = NA, qmethod = "double")
}


for ( alg in ALGORITHMS ) {
	for ( dir in CATALOGS ) {
		for ( interval in INTERVALS ) {
			file_name <- paste( 'int', interval, '.csv', sep='' )
			output_dir <- paste( OUTPUT_DIR, dir, alg, sep='/' )
			input_dir <- paste( INPUT_DIR, dir, sep='/')

			SUBS[[ alg ]]( input_dir, output_dir, file_name )
		}
	}
}
