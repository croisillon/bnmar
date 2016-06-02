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

sub_read_csv <- function ( file_name ) {
	ret <- read.csv( file_name, header=T, sep=";", stringsAsFactors=F );
	return(ret)
}

sub_create_structure <- function ( table, key ) {
	interval <- sub_interval_length( table[[ key ]][1] )

	fph <- sub_split_criteria( table[4], interval )
	ppf <- sub_split_criteria( table[5], interval )
	bpp <- sub_split_criteria( table[6], interval )
	bps <- sub_split_criteria( table[7], interval )

	df <- data.frame(fph=fph, ppf=ppf, bpp=bpp, bps=bps)

	return(df)
}

sub_create_structure_shift <- function ( table, key ) {
	interval <- sub_interval_length( table[[ key ]][1] )

	fph <- sub_split_criteria( table[5], interval )
	ppf <- sub_split_criteria( table[6], interval )
	bpp <- sub_split_criteria( table[7], interval )
	bps <- sub_split_criteria( table[8], interval )

	df <- data.frame(fph=fph, ppf=ppf, bpp=bpp, bps=bps)

	return(df)
}
