rm(list=ls())

args<-commandArgs(TRUE)

source('R/functions.r')

require(RWeka)
WPM("refresh-cache")
WPM("install-package", "XMeans")
WPM("load-package", "XMeans")

WORK_DIR <- args[1]
INPUT_DIR <- '01_split'
OUTPUT_DIR <- '02_clustering'

INPUT_DIR <- file.path( WORK_DIR, INPUT_DIR );
OUTPUT_DIR <- file.path( WORK_DIR, OUTPUT_DIR );

sub_xmeans <- function ( input_dir, output_dir, file_name ) {

	msg <- paste( "Running XMeans algorithm for file: ", file_name, sep='' )
	print(msg)

	coords_dir <- file.path(output_dir, 'coords')

	dir.create( output_dir, showWarnings=FALSE, recursive=TRUE,  mode='755' )
	dir.create( coords_dir, showWarnings=FALSE, recursive=TRUE,  mode='755' )
	
	input_file_name <- file.path( input_dir, file_name )

	file_name <- gsub("/", ".", file_name)
	output_file_name <- file.path( output_dir, file_name )

	file_name <- gsub("csv", "txt", file_name)
	coords_file_name <- file.path( coords_dir, file_name )

	table <- sub_read_csv( input_file_name )

	xmdf <- sub_create_structure_shift( table, c('fph') )
	drops <- c("X")
	table <- table[ , !(names(table) %in% drops)]

	xmclust <- XMeans(xmdf, c("-L", 10, "-H", 100, "-use-kdtree", "-K", "weka.core.neighboursearch.KDTree -P"))

	xmtable <- data.frame(src=table$src, dst=table$dst, port=table$port, fph=table$fph, ppf=table$ppf, bpp=table$bpp, bps=table$bps, cluster_id=xmclust$class_ids, old_cluster_id=table$cluster_id)

	sink(coords_file_name, append=FALSE, split=FALSE)
	print(xmclust$clusterer)
	sink();

	write.table(xmtable, file = output_file_name, sep = ";", col.names = NA, qmethod = "double")

	rm(table, xmdf, xmclust, xmtable)
}


list <- list.files( path=INPUT_DIR,full.names = F, recursive=T, pattern="*.csv", include.dirs=T )

for ( file in list ) {
	sub_xmeans( INPUT_DIR, OUTPUT_DIR, file )
}


