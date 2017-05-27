# If you want to run this script, you need execute steps below
# install.packages("RWekajars", dependencies=TRUE)
# install.packages("rJava", dependencies=TRUE)
# install.packages("RWeka", dependencies=TRUE)
# After this step, restart your R

# require(RWeka)
# WPM("refresh-cache")
# WPM("install-package", "XMeans")
# WPM("load-package", "XMeans")

source('R/functions.r')

require(RWeka)
WPM("refresh-cache")
WPM("install-package", "XMeans")
WPM("load-package", "XMeans")

sub_xmeans <- function ( input_dir, output_dir, file_name ) {

	msg <- paste( "Running XMeans algorithm for file: ", file_name, sep='' )
	print(msg)

	coords_dir <- file.path(output_dir, 'coords')

	dir.create( output_dir, showWarnings=FALSE, recursive=TRUE,  mode='755' )
	dir.create( coords_dir, showWarnings=FALSE, recursive=TRUE,  mode='755' )

	input_file_name <- file.path( input_dir, file_name )
	output_file_name <- file.path( output_dir, file_name )

	file_name <- gsub("csv", "txt", file_name)
	coords_file_name <- file.path( coords_dir, file_name )

	table <- sub_read_csv( input_file_name )

	xmdf <- sub_create_structure( table, c('fph') )

	xmclust <- XMeans(xmdf, c("-L", 10, "-H", 100, "-use-kdtree", "-K", "weka.core.neighboursearch.KDTree -P"))

	xmtable <- data.frame(src=table$src_ip, dst=table$dst_ip, port=table$dst_port, fph=table$fph, ppf=table$ppf, bpp=table$bpp, bps=table$bps, cluster_id=xmclust$class_ids)

	sink(coords_file_name, append=FALSE, split=FALSE)
	print(xmclust$clusterer)
	sink();

	write.table(xmtable, file = output_file_name, sep = ";", col.names = NA, qmethod = "double")

	rm(table, xmdf, xmclust, xmtable)
}

