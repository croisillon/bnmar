# If you want to run this script, you need execute steps below
# install.packages("RWekajars", dependencies=TRUE)
# install.packages("rJava", dependencies=TRUE)
# install.packages("RWeka", dependencies=TRUE)
# After this step, restart your R


# WPM("refresh-cache")
# WPM("install-package", "XMeans")
# WPM("load-package", "XMeans")

source('R/functions.r')

require(RWeka)

INSTALLED_XMEANS = 0

sub_xmeans <- function ( input_dir, output_dir, file_name ) {

	if ( !interactive() && !INSTALLED_XMEANS && require('RWeka') ) {
		print('Running XMeans installing. This operation can take several minutes...')
		WPM("install-package", "XMeans")
		INSTALLED_XMEANS <<- 1;
	}

	msg <- paste( "Running XMeans algorithm for file: ", file_name, sep='' )
	print(msg)

	dir.create( output_dir, showWarnings=FALSE, recursive=TRUE,  mode='755' )
	input_file_name <- file.path( input_dir, file_name )
	output_file_name <- file.path( output_dir, file_name )

	table <- sub_read_csv( input_file_name )

	xmdf <- sub_create_structure( table, c('fph') )

	xmclust <- XMeans(xmdf, c("-L", 10, "-H", 100, "-use-kdtree", "-K", "weka.core.neighboursearch.KDTree -P"))

	xmtable <- data.frame(src=table$src_ip, dst=table$dst_ip, port=table$dst_port, fph=table$fph, ppf=table$ppf, bpp=table$bpp, bps=table$bps, cluster_id=xmclust$class_ids)

	write.table(xmtable, file = output_file_name, sep = ";", col.names = NA, qmethod = "double")
	# write.table(summary, file = "xmeans_summary.csv", sep = ";", col.names = NA, qmethod = "double")

	rm(table, xmdf, xmclust, xmtable)
}

