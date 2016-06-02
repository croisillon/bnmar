rm(list=ls())

args<-commandArgs(TRUE)

WORK_DIR <- args[1]
INPUT_DIR <- 'binning'
OUTPUT_DIR <- 'clustering'

INTERVALS <- c( 2, 4, 6, 8, 10, 24 )
ALGORITHMS <- c( 'xmeans', 'dbscan', 'em' )

INPUT_DIR <- file.path( WORK_DIR, INPUT_DIR );
OUTPUT_DIR <- file.path( WORK_DIR, OUTPUT_DIR );

SUBS <- new.env( hash = TRUE, parent = emptyenv(), size = length( ALGORITHMS ) )


source(file='xmeans.r')
SUBS[[ 'xmeans' ]] <- sub_xmeans

source(file='dbscan.r')
SUBS[[ 'dbscan' ]] <- sub_dbscan

source(file='mclust.r')
SUBS[[ 'em' ]] <- sub_mclust


for ( alg in ALGORITHMS ) {
	for ( interval in INTERVALS ) {

		file_name <- paste( 'int', interval, '.csv', sep='' )
		output_dir <- file.path( OUTPUT_DIR, alg, sep='/' )

		SUBS[[ alg ]]( INPUT_DIR, output_dir, file_name )
	}
}
