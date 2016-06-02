rm(list=ls())

source('R/functions.r')

require(RWeka)

INSTALLED_XMEANS = 0

INPUT_DIR <- '/media/denis/WD/con/dm/07/249/01_split'
OUTPUT_DIR <- '/media/denis/WD/con/dm/07/249/02_clustering'

sub_xmeans <- function ( input_dir, output_dir, file_name ) {

	if ( !INSTALLED_XMEANS && require('RWeka') ) {
		print('Running XMeans installing. This operation can take several minutes...')
		WPM("install-package", "XMeans")
		INSTALLED_XMEANS <<- 1;
	}

	msg <- paste( "Running XMeans algorithm for file: ", file_name, sep='' )
	print(msg)

	dir.create( output_dir, showWarnings=FALSE, recursive=TRUE,  mode='755' )
	input_file_name <- file.path( input_dir, file_name )

	file_name <- gsub("/", ".", file_name)
	output_file_name <- file.path( output_dir, file_name )

	table <- sub_read_csv( input_file_name )

	xmdf <- sub_create_structure_shift( table, c('fph') )
	drops <- c("X")
	table <- table[ , !(names(table) %in% drops)]

	xmclust <- XMeans(xmdf, c("-L", 10, "-H", 100, "-use-kdtree", "-K", "weka.core.neighboursearch.KDTree -P"))

	xmtable <- data.frame(src=table$src, dst=table$dst, port=table$port, fph=table$fph, ppf=table$ppf, bpp=table$bpp, bps=table$bps, cluster_id=xmclust$class_ids, old_cluster_id=table$cluster_id)

	write.table(xmtable, file = output_file_name, sep = ";", col.names = NA, qmethod = "double")
	# write.table(summary, file = "xmeans_summary.csv", sep = ";", col.names = NA, qmethod = "double")

	rm(table, xmdf, xmclust, xmtable)
}


list <- list.files( path=INPUT_DIR,full.names = F, recursive=T, pattern="*.csv", include.dirs=T )

for ( file in list ) {
	sub_xmeans( INPUT_DIR, OUTPUT_DIR, file )
}


