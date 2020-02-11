package log

// Log levels defined for use with:
//   klog.V(__).Info

const (
	// INFO_LEVEL : This level is for anything which does not happen very often, and while not being
	//              an error, needs to be on the logs, because it's important information:
	//                * startup information
	//                * HA failovers
	//                * re-connections/disconnections
	//                * ...
	//              This level is not defined because you must use klog.Info helpers
	//
	// DEBUG_LEVEL : should be used to provide logs on often occurring events but, which could be helpful
	//               for debugging errors.
	DEBUG_LEVEL = 2
	// TRACE_LEVEL : must be used for debug level errors dumping lots of information which generally would
	//               be lest useful for debugging, but which could be eventually useful, for example tracing
	//               function entry/exit, parameters, structures, etc..
	TRACE_LEVEL = 3
)
